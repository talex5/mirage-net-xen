(*
 * Copyright (c) 2010-2013 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2014-2015 Citrix Inc
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Lwt.Infix
open Result

let src = Logs.Src.create "net-xen.backend" ~doc:"mirage-net-xen's Backend"
module Log = (val Logs.src_log src : Logs.LOG)

let return = Lwt.return

module Make(C: S.CONFIGURATION with type 'a io = 'a Lwt.t) = struct
  type +'a io = 'a Lwt.t
  type id = unit  (* Remove once mirage-types removes it *)
  type macaddr = Macaddr.t
  type buffer = Cstruct.t
  type page_aligned_buffer = Io_page.t
  type error = [
    | `Unknown of string
    | `Unimplemented
    | `Disconnected
  ]

  type stats = Stats.t = {
    mutable rx_bytes : int64;
    mutable rx_pkts : int32;
    mutable tx_bytes : int64;
    mutable tx_pkts : int32; 
  }

  type t = {
    channel: Eventchn.t;
    frontend_id: int;
    mac: Macaddr.t;
    backend_configuration: S.backend_configuration;
    to_netfront: (RX.Response.t,int) Ring.Rpc.Back.t;
    rx_reqs: RX.Request.t Lwt_sequence.t;         (* Grants we can write into *)
    from_netfront: (TX.Response.t,int) Ring.Rpc.Back.t;
    stats: Stats.t;
    write_mutex: Lwt_mutex.t;
  }

  let h = Eventchn.init ()
  let gnttab = Gnt.Gnttab.interface_open ()

  (* TODO: error handling *)
  let make ~domid ~device_id =
    let id = `Server (domid, device_id) in
    C.read_mac id >>= fun mac ->
    C.init_backend id Features.supported
    >>= fun backend_configuration ->
    let frontend_id = backend_configuration.S.frontend_id in
    C.read_frontend_configuration id >>= fun f ->
    let channel = Eventchn.bind_interdomain h frontend_id (int_of_string f.S.event_channel) in
    (* Flip TX and RX around *)
    let from_netfront =
      let tx_gnt = {Gnt.Gnttab.domid = frontend_id; ref = Int32.to_int f.S.tx_ring_ref} in
      let mapping = Gnt.Gnttab.map_exn gnttab tx_gnt true in
      let buf = Gnt.Gnttab.Local_mapping.to_buf mapping |> Io_page.to_cstruct in
      let sring = Ring.Rpc.of_buf ~buf ~idx_size:TX.total_size
        ~name:("Netif.Backend.TX." ^ backend_configuration.S.backend) in
      Ring.Rpc.Back.init ~sring in
    let to_netfront =
      let rx_gnt = {Gnt.Gnttab.domid = frontend_id; ref = Int32.to_int f.S.rx_ring_ref} in
      let mapping = Gnt.Gnttab.map_exn gnttab rx_gnt true in
      let buf = Gnt.Gnttab.Local_mapping.to_buf mapping |> Io_page.to_cstruct in
      let sring = Ring.Rpc.of_buf ~buf ~idx_size:RX.total_size
        ~name:("Netif.Backend.RX." ^ backend_configuration.S.backend) in
      Ring.Rpc.Back.init ~sring in
    let stats = Stats.create () in
    let rx_reqs = Lwt_sequence.create () in
    Eventchn.unmask h channel;
    C.connect id >>= fun () ->
    let write_mutex = Lwt_mutex.create () in
    return { channel; frontend_id; backend_configuration;
             to_netfront; from_netfront; rx_reqs; write_mutex;
             stats; mac }

  (* Check for incoming requests on the from_netfront ring.
     Packets received from this point on will go to [recv_buffer]. Historical
     packets have not been stored: we don't want to buffer the network. *)
  let listen (t: t) fn : unit Lwt.t =
    let module Recv = Assemble.Make(TX.Request) in
    let rec loop after =
      let q = ref [] in
      Ring.Rpc.Back.ack_requests t.from_netfront
        (fun slot ->
          match TX.Request.read slot with
          | Error msg -> Printf.printf "Netif.Backend.read_read TX has unparseable request: %s" msg
          | Ok req ->
            Stats.rx t.stats (Int64.of_int req.TX.Request.size);
            Log.info "Request received: id=%d offset=%d size=%d"
              TX.Request.(fun f -> f req.id req.offset req.size);
            q := req :: !q
        );
      (* -- at this point the ring slots may be overwritten, but the grants are still valid *)
      List.rev !q
      |> Recv.group_frames
      |> Lwt_list.iter_s (function
        | Error (e, _) -> e.TX.Request.impossible
        | Ok frame ->
            let data = Cstruct.create frame.Recv.total_size in
            let next = ref 0 in
            frame.Recv.fragments |> Lwt_list.iter_s (fun fragment ->
              let { TX.Request.flags = _; size = _; offset; gref; id } = fragment.Recv.msg in
              let gnt = { Gnt.Gnttab.
                domid = t.frontend_id;
                ref = Int32.to_int gref
              } in
              Gnt.Gnttab.with_mapping gnttab gnt false (function
                | None -> failwith "Failed to map grant"
                | Some mapping ->
                    let buf = Gnt.Gnttab.Local_mapping.to_buf mapping |> Io_page.to_cstruct in
                    Cstruct.blit buf offset data !next fragment.Recv.size;
                    next := !next + fragment.Recv.size;
                    let slot = Ring.Rpc.Back.(slot t.from_netfront (next_res_id t.from_netfront)) in
                    let resp = { TX.Response.id; status = TX.Response.OKAY } in
                    TX.Response.write resp slot;
                    return ()
              )
            ) >|= fun () ->
            assert (!next = Cstruct.len data);
            Lwt.async (fun () -> fn data)
      )
      >>= fun () ->
      let notify = Ring.Rpc.Back.push_responses_and_check_notify t.from_netfront in
      if notify then Eventchn.notify h t.channel;
      OS.Activations.after t.channel after
      >>= loop in
    loop OS.Activations.program_start

  (* We need [n] pages to send a packet to the frontend. The Ring.Back API
     gives us all the requests that are available at once. Since we may need
     fewer of this, stash them in the t.rx_reqs sequence. *)
  let get_n_grefs t n =
    let rec take seq = function
    | 0 -> []
    | n -> Lwt_sequence.take_l seq :: (take seq (n - 1)) in
    let rec loop after =
      let n' = Lwt_sequence.length t.rx_reqs in
      if n' >= n then return (take t.rx_reqs n)
      else begin
        Ring.Rpc.Back.ack_requests t.to_netfront
          (fun slot ->
            let req = RX.Request.read slot in
            ignore(Lwt_sequence.add_r req t.rx_reqs)
          );
        if Lwt_sequence.length t.rx_reqs <> n'
        then loop after
        else OS.Activations.after t.channel after >>= loop
      end in
    loop OS.Activations.program_start

  (* TODO: persistent grants? *)
  (* TODO: mutex? *)
  let write t buf =
    (* wait for a slot to be granted on the RX ring *)
    get_n_grefs t 1
    >>= fun reqs ->
    let req = List.hd reqs in
    let gnt = {Gnt.Gnttab.domid = t.frontend_id; ref = Int32.to_int req.RX.Request.gref} in
    let mapping = Gnt.Gnttab.map_exn gnttab gnt true in
    let frontend_buf = Gnt.Gnttab.Local_mapping.to_buf mapping |> Io_page.to_cstruct in
    Cstruct.blit buf 0 frontend_buf 0 (Cstruct.len buf);
    Gnt.Gnttab.unmap_exn gnttab mapping;
    let slot = Ring.Rpc.Back.(slot t.to_netfront (next_res_id t.to_netfront)) in
    RX.Response.(write { id = req.RX.Request.id; offset = 0; flags = Flags.empty; size = Ok (Cstruct.len buf) }) slot;
    Stats.tx t.stats (Int64.of_int (Cstruct.len buf));
    if Ring.Rpc.Back.push_responses_and_check_notify t.to_netfront
    then Eventchn.notify h t.channel;
    return ()

  let writev t buf =
    (* write for slots to be granted on the RX ring *)
    (* TODO: atomic! *)
    buf |> Lwt_list.iter_s (write t)

  let get_stats_counters t = t.stats
  let reset_stats_counters t = Stats.reset t.stats

  let mac t = t.mac
  
  let disconnect _t = failwith "TODO: disconnect"
end
