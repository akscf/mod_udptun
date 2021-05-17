<p>
 This module was written as helper tools for the mod_xconf (to expand abillities in point-to-point mode).<br>
 It gives to connect several separate hosts/networks between themselves (in point-to-point mode) in the situations when VPN or similar services not available/suitable. <br>
</p>

# Basic features
 - low latacy (good fit for RTP traffic)
 - passthrough mode (to exchange traffic as-is, without udptun envelope)
 - authentication and encryption traffic (based on RC4)
 - managing tunnels in real time (add, del, so on) 

<div aling="center">
 <img src='https://github.com/akscf/mod_udptun/blob/main/bin/schema.png'>
</div>

