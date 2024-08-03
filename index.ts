import express from 'express'
import { createServer } from 'http'
import { Server } from 'socket.io'
import * as frida from 'frida'
import { Client } from 'adb-ts'
import { readFileSync } from 'fs'
import path from 'path'
import { exec } from 'child_process'
import EventEmitter from 'events'
const pacakge = require('./package.json')

interface IData{
    type:string;
}

interface IRes{
    type:string;
}

const eventEmitter = new EventEmitter()

const filelist:string[] = ['frida', 'frida-server', 'frida-x86', 'frida-x86_64', 'frida-arm', 'frida-arm64']
const target:string = 'com.gameparadiso.milkchoco'
const frida_version:string = pacakge.dependencies.frida.split('^')[1] || '16.3.3'
const server_port:number = 3005
const localhost:string = '127.0.0.1'
let adb_localhost:string = '127.0.0.1'
let adb_port:string = '5555'

const app = express()
const server = createServer(app)
const io = new Server(server)

let socketConnected:boolean = false;
let adbId:string = '';
let fridaDevice:frida.Device;
let fridaServerExist:string = "";
let fridaServerPermission:boolean = false;
let fridaServerOn:boolean = false;
let processOn:boolean = false;
let cookie:string = '';

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'))
})

io.on('connection', (socket) => {
    if (socketConnected) {
        socket.emit('log', 'Already connected')
        return socket.disconnect()
    }
    console.log(`[Socket] Connected`)
    socketConnected = true
    socket.emit('init', {
        adb_address: adb_localhost,
        adb_port,
        adb_connected: adbId ? true : false,
        frida_connected: fridaDevice ? true : false,
        server_exist: fridaServerExist ? true : false,
        server_perm: fridaServerPermission,
        server_on: fridaServerOn,
        process_on: processOn,
        cookie
    })

    socket.on('api', (data:IData) => {
        console.log(`[Socket] API:`, data)
        eventEmitter.emit('api', data)
    })

    socket.on('exit', () => {
        console.log(`[Socket] Exit`)
        process.exit(0)
    })

    socket.on('statement', (data:{type:string, data?:{host:string; port:string}}) => {
        switch(data.type) {
            case 'adb-connect':
                connectAdbDevice(data.data?.host || adb_localhost, data.data?.port || adb_port)
                break;
            case 'frida-connect':
                connectFridaDevice(data.data?.host || adb_localhost, data.data?.port || adb_port)
                break;
                case 'server-exist':
                downloadFridaServer()
                break;
            case 'server-perm':
                checkFridaServerPermission()
                break;
            case 'server-on':
                startFridaServer()
                break;
            case 'process-on':
                main()
                break;
            default:
                break;
        }
    })

    eventEmitter.on('api-res', (data:IRes) => {socket.emit('api', data)})
    eventEmitter.on('log', (message:string) => {socket.emit('log', message)})
    eventEmitter.on('socket', (event:string, data:any) => {
        socket.emit(event, data)
    })
    socket.on('disconnect', () => {
        console.log(`[Socket] Disconnected`)
        socketConnected = false
        eventEmitter.removeAllListeners('api-res')
        eventEmitter.removeAllListeners('log')
        eventEmitter.removeAllListeners('socket')
    })
})

server.listen(server_port, () => {
    console.log(`[*] Server running on ${localhost}:${server_port}`)
    exec(`start http://${localhost}:${server_port}`)
})

const adb = new Client({})

const getUrl = (version:string, arch:string) => `https://github.com/frida/frida/releases/download/${version}/frida-server-${version}-android-${arch}.xz`

const checkCookieScript = readFileSync('./checkCookie.js', 'utf8')
const mainScript = readFileSync('./agent.js', 'utf8')

const log = (message:string) => {
    eventEmitter.emit('log', message)
    console.log(message)
}

const initState = (type:string, value:boolean|string) => {
    eventEmitter.emit('socket', 'statement', {type, value})
}

const runProcess = async (
    name: string,
    target:string,
    device:frida.Device,
    script:string,
    recieveCallback:(message: frida.Message, data: Buffer | null) => void,
    postCallback:() => void
):Promise<[
    () => Promise<void>,
    frida.Session,
    frida.Script
]> => {
    try{
        const pid = await device.spawn([target])
        processOn = true;
        initState('process-on', true)
        const session = await device.attach(target)
        log(`[${name}] Attached to ${target}`)
        const scr = await session.createScript(script)
        scr.message.connect(recieveCallback)
        await scr.load().then(() => {
            log(`[${name}] Script loaded`)
            postCallback()
        })
        await device.resume(target).then(() => log(`[${name}] Resumed`))
        const dispose = async () => {
            await scr.unload()
            await session.detach()
            await device.kill(target)
            log(`[${name}] Disposed`)
        }
        return [ dispose, session, scr ]
    } catch (err) {
        log(`[${name}] Error: ${err}`)
        return [async () => {}, {} as frida.Session, {} as frida.Script]
    }
}

const connectFridaDevice = async (host:string, port:string) => {
    const tar = await frida.getDeviceManager().addRemoteDevice(`${host}:${port}`)
    if (!tar) {
        log(`[*] Frida device not connected to ${host}:${port}`)
        initState('frida-connected', false)
        return false
    }
    log(`[*] Frida device connected to ${host}:${port}`)
    setTimeout(async () => {
        fridaDevice = await frida.getUsbDevice()
        fridaDevice.processCrashed.connect(() => {
            log(`[*] Process crashed`)
            fridaDevice = null as any
            initState('frida-connected', false)
        })
        initState('frida-connected', true)
        return true
    }, 1000);
}

const connectAdbDevice = async (host:string, port:string) => {
    log('[*] Try to connect to adb server')
    const result = await adb.connect(`${host}`, +port)
    if (!result) {
        log('[*] Failed to connect to adb server')
        adbId = ''
        initState('adb-connected', false)
        return false
    }
    log(`[*] Connected to adb server ${result}`)
    adbId = result
    initState('adb-connected', true)
    return true
}

const checkFridaServer = async () => {
    log('[*] Checking frida server')
    if(adbId === '') return log('[*] ADB not connected')
    const files = await adb.readDir(adbId, '/data/local/tmp')
    const file = files.find(file => filelist.includes(file.name))
    if (!file) {
        log('[*] Frida server not found')
        fridaServerExist = ""
        initState('server-exist', fridaServerExist)
        return false
    }
    log('[*] Frida server found')
    fridaServerExist = file.name
    initState('server-exist', fridaServerExist)
    return true
}

const checkFridaServerPermission = async () => {
    log('[*] Checking frida server permission')
    if(adbId === '') return log('[*] ADB not connected')
    const permissions = await adb.shell(adbId, `ls -l /data/local/tmp/${fridaServerExist}`)
    if (!permissions.includes('rwxrwxrwx')) {
        try{
            log(`[*] Changing permissions`)
            const chmod = await adb.shell(adbId, `chmod 777 /data/local/tmp/${fridaServerExist}`)
            log(`[*] Permissions changed`)
            fridaServerPermission = true
            initState('server-perm', true)
            return true
        } catch (err) {
            log(`[*] Failed to change permissions`)
            fridaServerPermission = false
            initState('server-perm', false)
            return false
        }
    }
    log(`[*] Permissions OK`)
    fridaServerPermission = true
    return true
}

const startFridaServer = async () => {
    log('[*] Starting frida server')
    if(adbId === '') {
        log('[*] ADB not connected')
        return false
    }
    const server = adb.shell(adbId, `su -c /data/local/tmp/${fridaServerExist}`)
    log(`[*] Frida server started`)
    fridaServerOn = true
    initState('server-on', true)
    server.then(() => {
        log(`[*] Frida server stopped`)
        fridaServerOn = false
        initState('server-on', false)
    })
    return true
}

const downloadFridaServer = async () => {
    log('[*] Downloading frida server')
    if(adbId === '') return log('[*] ADB not connected')
    const os = await adb.shell(adbId, 'getprop ro.product.cpu.abi')
    let arch = 'arm'
    if (os.includes('x86')) {
        arch = 'x86'
    }
    const bits = await adb.shell(adbId, 'getprop ro.product.cpu.abilist')
    if (bits.includes('64')) {
        if(arch === 'x86') arch = 'x86_64'
        else arch = 'arm64'
    }
    const server = getUrl(frida_version, arch)
    try{
        const download = await adb.shell(adbId, `wget -no-check-certificate ${server} -O /data/local/tmp/frida-server.xz`)
        const extract = await adb.shell(adbId, `unxz /data/local/tmp/frida-server.xz`)
        const chmod = await adb.shell(adbId, `chmod 777 /data/local/tmp/frida-server`)
        log('[*] Downloaded frida server')
        return true
    } catch (err) {
        log(`[*] You need to download frida server manually and push it to /data/local/tmp/ \n${server} \nadb push frida-server /data/local/tmp/`)
        exec(`start ${server}`)
        return false
    }
}

async function main() {
    if(!fridaDevice) {
        fridaDevice = await frida.getUsbDevice()
        if (!fridaDevice) return log('[*] Frida device not connected')
    }
    const [disposeCookie, cses] = await runProcess("checkCookie", target, fridaDevice, checkCookieScript, async (message, data) => {
        if (message.type === 'error') {
            log(`Error: ${message.description}`)
            return;
        };
        if (message.payload.type === 'cookieResult' && message.payload.res) {
            cookie = message.payload.res
            initState('cookie', cookie)
            log(`[*] Cookie found ${cookie}`)
            setTimeout(async () => {
                log(`[*] Restarting app...`)
                await disposeCookie()
                const [disposeMain, ses, scr] = await runProcess("main", target, fridaDevice,
                mainScript.replace('/*cookie*/', cookie),
                (message, data) => {
                    if (message.type === 'error') {
                        log(`Error: ${message.description}`)
                        return;
                    };
                    if (message.payload.type === 'api') {
                        eventEmitter.emit('api-res', message.payload.res)
                    } else if(message.payload.type === 'init'){
                        eventEmitter.emit('socket', 'gameInit', message.payload.res)
                    } else {
                        log(message.payload)
                    }
                },() => {
                    eventEmitter.on('api', async (data:IData) => {
                        log(`[*] Sending API: ${data.type}`)
                        scr.post(data)
                    })
                });
                ses.detached.connect(async () => {
                    log(`[*] Session detached`);
                    processOn = false;
                    initState('process-on', false)
                    return;
                })
            }, 3000);
        } else {
            log(message.payload)
        }
    },() => {});
    cses.detached.connect(async () => {
        log(`[*] Session detached`);
        processOn = false;
        initState('process-on', false)
        return;
    })
}

adb.listDevices().then(async devices => {
    log(`[*] Found ${devices.length} devices`)
    await connectFridaDevice(adb_localhost, adb_port)
    if (devices.length === 0) {
        log('[*] No device found.')
        await connectAdbDevice(adb_localhost, adb_port)
    } else {
        adbId = devices[0].id
        initState('adb-connected', true)
        log(`[*] Using ${adbId}`)
    }
    if(adbId === '') return log('[*] ADB not connected')
    // check frida server
    await checkFridaServer()
    if (!fridaServerExist) {
        // download frida server
        const success = await downloadFridaServer()
        if (!success) return;
    }
    // check permissions
    await checkFridaServerPermission()
    // start server
    await startFridaServer()
    setTimeout(() => {
        if (!fridaServerOn) {
            log('[*] Frida server not running')
            return;
        }
        main().catch(err => console.error(err))
    }, 1000);
})