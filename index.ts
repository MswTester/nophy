import * as frida from 'frida'
import { Client } from 'adb-ts'

const filelist = ['frida', 'frida-server', 'frida-x86', 'frida-x86_64', 'frida-arm', 'frida-arm64']
const target = 'com.gameparadiso.milkchoco'
const adb_port = 5555
const adb = new Client({})

const getUrl = (version:string, arch:string) => `https://github.com/frida/frida/releases/download/${version}/frida-server-${version}-android-${arch}.xz`

async function main(id:string) {
    const device = await frida.getUsbDevice()
    const pid = await device.spawn([target])
    const session = await device.attach(target)
    console.log('Device connected', session)
    const checkCookie = await session.createScript(`
    setImmediate(function() {
        Java.perform(() => {
            let Cocos2dxActivity = Java.use("org.cocos2dx.lib.Cocos2dxActivity");
            Cocos2dxActivity["getCookie"].implementation = function (str) {
                let result = this["getCookie"](str);
                send(\`cookieResult$=\${result}\`);
                return \`\${result}\`;
            };
        });
    });
    `);
    checkCookie.message.connect(async (message, data) => {
        if (message.type === 'error') return console.error('Error from frida script');
        const res = (message.payload as string).split('$=');
        if (res[0] === 'cookieResult' && res[1]) {
            console.log('Cookie found', res[1])
            console.log('Restarting app...')
            await checkCookie.unload()
            await session.detach()
            await device.kill(target)
            console.log('Killed app')
            const new_pid = await device.spawn([target])
            const new_session = await device.attach(target)
            const blockXigncode = await new_session.createScript(`
            setImmediate(function() {
                Java.perform(() => {
                    let XigncodeClientSystem = Java.use("com.wellbia.xigncode.XigncodeClientSystem");
                        XigncodeClientSystem["initialize"].implementation = function (activity,str,str2,str3,callback) {
                        send(\`XigncodeClientSystem.initialize is called: activity$=\${activity}, str=\${str}, str2=\${str2}, str3=\${str3}, callback=\${callback}\`);
                        return 0;
                    };
                    let Cocos2dxActivity = Java.use("org.cocos2dx.lib.Cocos2dxActivity");
                    Cocos2dxActivity["getCookie"].implementation = function (str) {
                        let result = this["getCookie"](str);
                        send(\`Successfully joined!\`);
                        return \`${res[1]}\`;
                    };
                });
            });
            `);
            blockXigncode.message.connect(async (message, data) => {
                if (message.type === 'error') return console.error('Error from frida script');
                const res = (message.payload as string).split('$=');
                console.log(message.payload)
            });
            await blockXigncode.load()
            console.log('blockXigncode loaded')
            await device.resume(target)
            console.log('Resumed[2]');
        } else {
            console.log(message.payload)
        }
    });
    await checkCookie.load()
    console.log('checkCookie loaded')
    await device.resume(target)
    console.log('Resumed[1]');
}

adb.listDevices().then(async devices => {
    await frida.getDeviceManager().addRemoteDevice(`127.0.0.1:${adb_port}`)
    if (devices.length === 0) {
        console.error('Try to connect to adb server')
        const result = await adb.connect(`127.0.0.1`, adb_port)
        if (!result) {
            console.error('Failed to connect to adb server')
            process.exit(1)
        }
        console.log('Connected to adb server', result)
        devices = await adb.listDevices()
    }
    let id = devices[0].id
    const files = await adb.readDir(id, '/data/local/tmp')
    const file = files.find(file => filelist.includes(file.name))
    if (!file) {
        console.log('Downloading frida server')
        const os = await adb.shell(id, 'getprop ro.product.cpu.abi')
        let arch = 'arm'
        if (os.includes('x86')) {
            arch = 'x86'
        }
        const bits = await adb.shell(id, 'getprop ro.product.cpu.abilist')
        if (bits.includes('64')) {
            if(arch === 'x86') arch = 'x86_64'
            else arch = 'arm64'
        }
        const server = getUrl('16.2.1', arch)
        try{
            const download = await adb.shell(id, `wget -no-check-certificate ${server} -O /data/local/tmp/frida-server.xz`)
            const extract = await adb.shell(id, `unxz /data/local/tmp/frida-server.xz`)
            const chmod = await adb.shell(id, `chmod 777 /data/local/tmp/frida-server`)
            console.log('Downloaded frida server')
        } catch (err) {
            console.log(`You need to download frida server manually and push it to /data/local/tmp/ \n${server} \nadb push frida-server /data/local/tmp/`)
            process.exit(1)
        }
    }
    // check permissions
    const permissions = await adb.shell(id, 'ls -l /data/local/tmp/frida-server')
    if (!permissions.includes('rwxrwxrwx')) {
        const chmod = await adb.shell(id, `chmod 777 /data/local/tmp/frida-server`)
    }
    adb.shell(id, `su -c /data/local/tmp/${file?.name}`)
    setTimeout(() => {
        main(id).catch(err => console.error(err))
    }, 1000);
})