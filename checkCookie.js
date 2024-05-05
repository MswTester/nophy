setTimeout(() => {
    setImmediate(function() {
        Java.perform(() => {
            let Cocos2dxActivity = Java.use("org.cocos2dx.lib.Cocos2dxActivity");
            Cocos2dxActivity["getCookie"].implementation = function (str) {
                let result = this["getCookie"](str);
                send({type: 'cookieResult', res: result});
                return `${result}`;
            };
        });
    });
}, 100);