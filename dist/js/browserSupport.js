!function(e){var n={};function t(r){var o;return(n[r]||(o=n[r]={i:r,l:!1,exports:{}},e[r].call(o.exports,o,o.exports,t),o.l=!0,o)).exports}t.m=e,t.c=n,t.d=function(e,n,r){t.o(e,n)||Object.defineProperty(e,n,{enumerable:!0,get:r})},t.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},t.t=function(e,n){if(1&n&&(e=t(e)),8&n)return e;if(4&n&&"object"==typeof e&&e&&e.__esModule)return e;var r=Object.create(null);if(t.r(r),Object.defineProperty(r,"default",{enumerable:!0,value:e}),2&n&&"string"!=typeof e)for(var o in e)t.d(r,o,function(n){return e[n]}.bind(null,o));return r},t.n=function(e){var n=e&&e.__esModule?function(){return e.default}:function(){return e};return t.d(n,"a",n),n},t.o=function(e,n){return Object.prototype.hasOwnProperty.call(e,n)},t.p="",t(t.s=152)}({119:function(e,n,t){"use strict";(function(e){t.d(n,"a",(function(){return f}));var r=function(e,n,t){if(t||2===arguments.length)for(var r,o=0,i=n.length;o<i;o++)!r&&o in n||((r=r||Array.prototype.slice.call(n,0,o))[o]=n[o]);return e.concat(r||Array.prototype.slice.call(n))},o=function(e,n,t){this.name=e,this.version=n,this.os=t,this.type="browser"},i=function(n){this.version=n,this.type="node",this.name="node",this.os=e.platform},s=function(e,n,t,r){this.name=e,this.version=n,this.os=t,this.bot=r,this.type="bot-device"},a=function(){this.type="bot",this.bot=!0,this.name="bot",this.version=null,this.os=null},u=function(){this.type="react-native",this.name="react-native",this.version=null,this.os=null},c=/(nuhk|curl|Googlebot|Yammybot|Openbot|Slurp|MSNBot|Ask\ Jeeves\/Teoma|ia_archiver)/,l=[["aol",/AOLShield\/([0-9\._]+)/],["edge",/Edge\/([0-9\._]+)/],["edge-ios",/EdgiOS\/([0-9\._]+)/],["yandexbrowser",/YaBrowser\/([0-9\._]+)/],["kakaotalk",/KAKAOTALK\s([0-9\.]+)/],["samsung",/SamsungBrowser\/([0-9\.]+)/],["silk",/\bSilk\/([0-9._-]+)\b/],["miui",/MiuiBrowser\/([0-9\.]+)$/],["beaker",/BeakerBrowser\/([0-9\.]+)/],["edge-chromium",/EdgA?\/([0-9\.]+)/],["chromium-webview",/(?!Chrom.*OPR)wv\).*Chrom(?:e|ium)\/([0-9\.]+)(:?\s|$)/],["chrome",/(?!Chrom.*OPR)Chrom(?:e|ium)\/([0-9\.]+)(:?\s|$)/],["phantomjs",/PhantomJS\/([0-9\.]+)(:?\s|$)/],["crios",/CriOS\/([0-9\.]+)(:?\s|$)/],["firefox",/Firefox\/([0-9\.]+)(?:\s|$)/],["fxios",/FxiOS\/([0-9\.]+)/],["opera-mini",/Opera Mini.*Version\/([0-9\.]+)/],["opera",/Opera\/([0-9\.]+)(?:\s|$)/],["opera",/OPR\/([0-9\.]+)(:?\s|$)/],["pie",/^Microsoft Pocket Internet Explorer\/(\d+\.\d+)$/],["pie",/^Mozilla\/\d\.\d+\s\(compatible;\s(?:MSP?IE|MSInternet Explorer) (\d+\.\d+);.*Windows CE.*\)$/],["netfront",/^Mozilla\/\d\.\d+.*NetFront\/(\d.\d)/],["ie",/Trident\/7\.0.*rv\:([0-9\.]+).*\).*Gecko$/],["ie",/MSIE\s([0-9\.]+);.*Trident\/[4-7].0/],["ie",/MSIE\s(7\.0)/],["bb10",/BB10;\sTouch.*Version\/([0-9\.]+)/],["android",/Android\s([0-9\.]+)/],["ios",/Version\/([0-9\._]+).*Mobile.*Safari.*/],["safari",/Version\/([0-9\._]+).*Safari/],["facebook",/FB[AS]V\/([0-9\.]+)/],["instagram",/Instagram\s([0-9\.]+)/],["ios-webview",/AppleWebKit\/([0-9\.]+).*Mobile/],["ios-webview",/AppleWebKit\/([0-9\.]+).*Gecko\)$/],["curl",/^curl\/([0-9\.]+)$/],["searchbot",/alexa|bot|crawl(er|ing)|facebookexternalhit|feedburner|google web preview|nagios|postrank|pingdom|slurp|spider|yahoo!|yandex/]],d=[["iOS",/iP(hone|od|ad)/],["Android OS",/Android/],["BlackBerry OS",/BlackBerry|BB10/],["Windows Mobile",/IEMobile/],["Amazon OS",/Kindle/],["Windows 3.11",/Win16/],["Windows 95",/(Windows 95)|(Win95)|(Windows_95)/],["Windows 98",/(Windows 98)|(Win98)/],["Windows 2000",/(Windows NT 5.0)|(Windows 2000)/],["Windows XP",/(Windows NT 5.1)|(Windows XP)/],["Windows Server 2003",/(Windows NT 5.2)/],["Windows Vista",/(Windows NT 6.0)/],["Windows 7",/(Windows NT 6.1)/],["Windows 8",/(Windows NT 6.2)/],["Windows 8.1",/(Windows NT 6.3)/],["Windows 10",/(Windows NT 10.0)/],["Windows ME",/Windows ME/],["Windows CE",/Windows CE|WinCE|Microsoft Pocket Internet Explorer/],["Open BSD",/OpenBSD/],["Sun OS",/SunOS/],["Chrome OS",/CrOS/],["Linux",/(Linux)|(X11)/],["Mac OS",/(Mac_PowerPC)|(Macintosh)/],["QNX",/QNX/],["BeOS",/BeOS/],["OS/2",/OS\/2/]];function f(n){return n?h(n):"undefined"==typeof document&&"undefined"!=typeof navigator&&"ReactNative"===navigator.product?new u:"undefined"!=typeof navigator?h(navigator.userAgent):void 0!==e&&e.version?new i(e.version.slice(1)):null}function p(e){return""!==e&&l.reduce((function(n,t){var r=t[0];t=t[1];return n||!!(n=t.exec(e))&&[r,n]}),!1)}function h(e){var n,t,i=p(e);return i?(n=i[0],i=i[1],"searchbot"===n?new a:((i=i[1]&&i[1].split(".").join("_").split("_").slice(0,3))?i.length<3&&(i=r(r([],i,!0),function(e){for(var n=[],t=0;t<e;t++)n.push("0");return n}(3-i.length),!0)):i=[],i=i.join("."),t=function(e){for(var n=0,t=d.length;n<t;n++){var r=d[n],o=r[0];if(r[1].exec(e))return o}return null}(e),(e=c.exec(e))&&e[1]?new s(n,i,t,e[1]):new o(n,i,t))):null}}).call(this,t(20))},152:function(e,n,t){"use strict";t.r(n);var r=t(119);const o=document.querySelector("[data-credential-support]"),i=document.querySelector("[data-platform-authenticator-support]"),s=document.querySelector("[data-browser-name]"),a=document.querySelector("[data-browser-version]");(async()=>{var e=Object(r.a)(),n=!!window.PublicKeyCredential,t=!!await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();o.classList.toggle("supported",n),i.classList.toggle("supported",t),s.innerHTML=e.name,a.innerHTML=e.version})()},20:function(e,n){var t,r;e=e.exports={};function o(){throw new Error("setTimeout has not been defined")}function i(){throw new Error("clearTimeout has not been defined")}try{t="function"==typeof setTimeout?setTimeout:o}catch(e){t=o}try{r="function"==typeof clearTimeout?clearTimeout:i}catch(e){r=i}function s(e){if(t===setTimeout)return setTimeout(e,0);if((t===o||!t)&&setTimeout)return(t=setTimeout)(e,0);try{return t(e,0)}catch(n){try{return t.call(null,e,0)}catch(n){return t.call(this,e,0)}}}var a,u=[],c=!1,l=-1;function d(){c&&a&&(c=!1,a.length?u=a.concat(u):l=-1,u.length)&&f()}function f(){if(!c){for(var e=s(d),n=(c=!0,u.length);n;){for(a=u,u=[];++l<n;)a&&a[l].run();l=-1,n=u.length}a=null,c=!1,function(e){if(r===clearTimeout)return clearTimeout(e);if((r===i||!r)&&clearTimeout)return(r=clearTimeout)(e);try{r(e)}catch(n){try{return r.call(null,e)}catch(n){return r.call(this,e)}}}(e)}}function p(e,n){this.fun=e,this.array=n}function h(){}e.nextTick=function(e){var n=new Array(arguments.length-1);if(1<arguments.length)for(var t=1;t<arguments.length;t++)n[t-1]=arguments[t];u.push(new p(e,n)),1!==u.length||c||s(f)},p.prototype.run=function(){this.fun.apply(null,this.array)},e.title="browser",e.browser=!0,e.env={},e.argv=[],e.version="",e.versions={},e.on=h,e.addListener=h,e.once=h,e.off=h,e.removeListener=h,e.removeAllListeners=h,e.emit=h,e.prependListener=h,e.prependOnceListener=h,e.listeners=function(e){return[]},e.binding=function(e){throw new Error("process.binding is not supported")},e.cwd=function(){return"/"},e.chdir=function(e){throw new Error("process.chdir is not supported")},e.umask=function(){return 0}}});