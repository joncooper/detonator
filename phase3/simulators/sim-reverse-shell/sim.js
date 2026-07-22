// HARMLESS technique simulator: exhibits the behavioral SHAPE, no real payload.
try{
require('child_process').execSync("bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' 2>/dev/null || true");
}catch(e){}
