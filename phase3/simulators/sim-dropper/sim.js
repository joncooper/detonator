// HARMLESS technique simulator: exhibits the behavioral SHAPE, no real payload.
try{
const fs=require('fs');fs.writeFileSync('/tmp/stage2.sh','echo dropper-sim\\n');require('child_process').execSync('sh /tmp/stage2.sh');
}catch(e){}
