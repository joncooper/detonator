// HARMLESS technique simulator: exhibits the behavioral SHAPE, no real payload.
try{
require('net').connect(3333,'pool.fake-miner.example').on('error',()=>{});
}catch(e){}
