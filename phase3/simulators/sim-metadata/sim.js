// HARMLESS technique simulator: exhibits the behavioral SHAPE, no real payload.
try{
require('http').get('http://169.254.169.254/latest/meta-data/').on('error',()=>{});
}catch(e){}
