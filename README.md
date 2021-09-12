<p>
  A helper module was written to work in tandem with mod_xconf (to expand abillities in unicast mode), one gives opportunity to connect separated hosts/networks between themselves and exchanging UPD traffic. 
  It can be useful in the situation when VPN (or similar services) not available or you can't use it for any reasons (in our case). <br>
</p>

### Features
 - low latacy (good fit for RTP)
 - bypass mode (exchange packets as-is, without udptun headers)
 - traffic authentication and encryption (based on RC4)
 - managing tunnels in a real time (add, del, ...)

### Related links
 - [Workflow diagram](https://akscf.org/files/mod_udptun/wf0.png)

