const os = import.meta.use('os');
const fs = import.meta.use('fs');


let ext = 'so';
if (os.uname().sysname.startsWith('Windows')) ext = 'dll';
if (fs.exists('native.' + ext)) { 
    import.meta.register('ext:quic', './native.' + ext);
}
export default import.meta.use('ext:quic');