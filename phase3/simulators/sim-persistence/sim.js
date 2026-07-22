// HARMLESS technique simulator: exhibits the behavioral SHAPE, no real payload.
try{
require('fs').appendFileSync(require('os').homedir()+'/.bashrc','# behavioral-sim marker\\n');
}catch(e){}
