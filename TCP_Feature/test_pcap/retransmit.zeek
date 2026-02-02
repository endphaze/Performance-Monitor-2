event tcp_retransmit(c: connection, is_orig: bool, seq: count, len: count, data_len: count)
    {
    print fmt("[%s] Retransmit! %s:%d -> %s:%d | Seq: %d | Len: %d",
              network_time(),
              c$id$orig_h, c$id$orig_p,
              c$id$resp_h, c$id$resp_p,
              seq, len);
    }
