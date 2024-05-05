setTimeout(() => {
    setImmediate(function() {
        Java.perform(() => {
            let XigncodeClientSystem = Java.use("com.wellbia.xigncode.XigncodeClientSystem");
                XigncodeClientSystem["initialize"].implementation = function (activity,str,str2,str3,callback) {
                send(`XigncodeClientSystem.initialize is called: activity$=${activity}, str=${str}, str2=${str2}, str3=${str3}, callback=${callback}`);
                return 0;
            };
            let Cocos2dxActivity = Java.use("org.cocos2dx.lib.Cocos2dxActivity");
            Cocos2dxActivity["getCookie"].implementation = function (str) {
                let result = this["getCookie"](str);
                send(`Successfully joined!`);
                return '/*cookie*/';
            };
            gameInit();

            async function onAPI(message) {
                if(message['type'] === 'init') {
                    gameInit();
                } else if(message['type'] === 'new-scan'){
                    const data = message['data']
                    let addrs = []
                    Memory.scan(ptr(data.base), data.size, data.value, {
                        onMatch: function(address, size) {
                            let value = arrayBufferToString(Memory.readByteArray(address, size));
                            addrs.push({address, value})
                        },
                        onComplete: function() {
                            send({
                                type: 'api',
                                res: {type: 'new-scan', addrs}
                            });
                        }
                    });
                } else if(message['type'] === 'next-scan'){
                    const data = message['data']
                    send({
                        type: 'api',
                        res: {
                            type: 'next-scan',
                            addrs:data.addrs.filter(addr =>
                                arrayBufferToString(
                                    Memory.readByteArray(ptr(addr.address), data.size)
                                ) === data.value
                            )
                        }

                    });
                } else if (message['type'] === 'readMemory') {
                    let address = message['address'];
                    let size = message['size'];
                    let dataType = message['dataType'];
                    let data = Memory.readByteArray(ptr(address), size);
                    send({
                        'type': 'api',
                        'res': {
                            'type': 'readMemory',
                            'address': address,
                            'data': data
                        }
                    });
                } else if (message['type'] === 'writeMemory') {
                    let address = message['address'];
                    let data = message['data'];
                    let dataType = message['dataType'];
                    Memory.writeByteArray(ptr(address), data);
                    send({
                        'type': 'api',
                        'res': {
                            'type': 'writeMemory',
                            'address': address
                        }
                    });
                } else if (message['type'] === 'callFunction') {
                    let address = message['address'];
                    let args = message['args'];
                    let retType = message['retType'];
                    let ret = new NativeFunction(ptr(address), retType, args.map(arg => arg.type)).apply(null, args.map(arg => arg.value));
                    send({
                        type:'api',
                        res: {
                            'type': 'callFunction',
                            'address': address,
                            'ret': ret
                        }
                    });
                } else if(message['type'] === 'getAllModules') {
                    let modules = Process.enumerateModulesSync();
                    send({
                        type:'api',
                        res: {
                            'type': 'getAllModules',
                            'modules': modules
                        }
                    });
                } else {
                    send({
                        type:'api',
                        res: {
                            'type': 'unknown',
                            'message': message
                        }
                    });
                }
                recv(onAPI);
            }
            recv(onAPI);
        });
    });
}, 100);

function gameInit(){
    send({
        type:'init',
        res: Process.enumerateModulesSync()
    })
}

function arrayBufferToString(buffer) {
    var uint8Array = new Uint8Array(buffer);
    var hexString = Array.from(uint8Array, byte => byte.toString(16).toUpperCase().padStart(2, '0')).join(' ');
    return hexString;
}