!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?e(exports):"function"==typeof define&&define.amd?define(["exports"],e):e((t="undefined"!=typeof globalThis?globalThis:t||self).SaltyCrypto={})}(this,(function(t){"use strict";function e(t,e){return t<<e|t>>>32-e}function s(t,s,i,h,r){t[s]+=t[i],t[r]^=t[s],t[r]=e(t[r],16),t[h]+=t[r],t[i]^=t[h],t[i]=e(t[i],12),t[s]+=t[i],t[r]^=t[s],t[r]=e(t[r],8),t[h]+=t[r],t[i]^=t[h],t[i]=e(t[i],7)}function i(t,e,s,i){t[0]+=1634760805,t[1]+=857760878,t[2]+=2036477234,t[3]+=1797285236,t[4]+=e.getUint32(0,!0),t[5]+=e.getUint32(4,!0),t[6]+=e.getUint32(8,!0),t[7]+=e.getUint32(12,!0),t[8]+=e.getUint32(16,!0),t[9]+=e.getUint32(20,!0),t[10]+=e.getUint32(24,!0),t[11]+=e.getUint32(28,!0),t[12]+=s,t[13]+=i.getUint32(0,!0),t[14]+=i.getUint32(4,!0),t[15]+=i.getUint32(8,!0)}function h(t,e,h){const r=new Uint32Array(16);i(r,t,e,h);for(let t=0;t<20;t+=2)s(r,0,4,8,12),s(r,1,5,9,13),s(r,2,6,10,14),s(r,3,7,11,15),s(r,0,5,10,15),s(r,1,6,11,12),s(r,2,7,8,13),s(r,3,4,9,14);return i(r,t,e,h),r}function r(t,e,s,i,r=0,n=s.byteLength){const a=n>>6,o=63&n;for(let n=0;n<a;n++){const a=h(t,r+n,e);for(let t=0;t<64;t++)i[(n<<6)+t]=s[(n<<6)+t]^a[t>>2]>>((3&t)<<3)}if(0!==o){const n=h(t,r+a,e);for(let t=0;t<o;t++)i[(a<<6)+t]=s[(a<<6)+t]^n[t>>2]>>((3&t)<<3)}}var n=Object.freeze({__proto__:null,CHACHA20_BLOCKBYTES:64,CHACHA20_KEYBYTES:32,CHACHA20_NONCEBYTES:12,chacha20:r,chacha20_block:h,chacha20_quarter_round:s});class a{static digest(t,e){const s=new a(t);s.update(e,0,e.byteLength);const i=new Uint8Array(a.TAGBYTES);return s.finish(i,0),i}constructor(t){this.key=t,this.buffer=new Uint8Array(16),this.r=new Uint16Array(10),this.h=new Uint16Array(10),this.pad=new Uint16Array(8),this.leftover=0,this.fin=0;const e=255&t[0]|(255&t[1])<<8;this.r[0]=8191&e;const s=255&t[2]|(255&t[3])<<8;this.r[1]=8191&(e>>>13|s<<3);const i=255&t[4]|(255&t[5])<<8;this.r[2]=7939&(s>>>10|i<<6);const h=255&t[6]|(255&t[7])<<8;this.r[3]=8191&(i>>>7|h<<9);const r=255&t[8]|(255&t[9])<<8;this.r[4]=255&(h>>>4|r<<12),this.r[5]=r>>>1&8190;const n=255&t[10]|(255&t[11])<<8;this.r[6]=8191&(r>>>14|n<<2);const a=255&t[12]|(255&t[13])<<8;this.r[7]=8065&(n>>>11|a<<5);const o=255&t[14]|(255&t[15])<<8;this.r[8]=8191&(a>>>8|o<<8),this.r[9]=o>>>5&127,this.pad[0]=255&t[16]|(255&t[17])<<8,this.pad[1]=255&t[18]|(255&t[19])<<8,this.pad[2]=255&t[20]|(255&t[21])<<8,this.pad[3]=255&t[22]|(255&t[23])<<8,this.pad[4]=255&t[24]|(255&t[25])<<8,this.pad[5]=255&t[26]|(255&t[27])<<8,this.pad[6]=255&t[28]|(255&t[29])<<8,this.pad[7]=255&t[30]|(255&t[31])<<8}blocks(t,e,s){const i=this.fin?0:2048;let h=this.h[0],r=this.h[1],n=this.h[2],a=this.h[3],o=this.h[4],l=this.h[5],c=this.h[6],f=this.h[7],u=this.h[8],y=this.h[9],p=this.r[0],d=this.r[1],m=this.r[2],g=this.r[3],b=this.r[4],K=this.r[5],w=this.r[6],_=this.r[7],A=this.r[8],E=this.r[9];for(;s>=16;){const U=255&t[e+0]|(255&t[e+1])<<8;h+=8191&U;const v=255&t[e+2]|(255&t[e+3])<<8;r+=8191&(U>>>13|v<<3);const M=255&t[e+4]|(255&t[e+5])<<8;n+=8191&(v>>>10|M<<6);const S=255&t[e+6]|(255&t[e+7])<<8;a+=8191&(M>>>7|S<<9);const k=255&t[e+8]|(255&t[e+9])<<8;o+=8191&(S>>>4|k<<12),l+=k>>>1&8191;const L=255&t[e+10]|(255&t[e+11])<<8;c+=8191&(k>>>14|L<<2);const H=255&t[e+12]|(255&t[e+13])<<8;f+=8191&(L>>>11|H<<5);const N=255&t[e+14]|(255&t[e+15])<<8;u+=8191&(H>>>8|N<<8),y+=N>>>5|i;let x=0,P=x;P+=h*p,P+=r*(5*E),P+=n*(5*A),P+=a*(5*_),P+=o*(5*w),x=P>>>13,P&=8191,P+=l*(5*K),P+=c*(5*b),P+=f*(5*g),P+=u*(5*m),P+=y*(5*d),x+=P>>>13,P&=8191;let B=x;B+=h*d,B+=r*p,B+=n*(5*E),B+=a*(5*A),B+=o*(5*_),x=B>>>13,B&=8191,B+=l*(5*w),B+=c*(5*K),B+=f*(5*b),B+=u*(5*g),B+=y*(5*m),x+=B>>>13,B&=8191;let T=x;T+=h*m,T+=r*d,T+=n*p,T+=a*(5*E),T+=o*(5*A),x=T>>>13,T&=8191,T+=l*(5*_),T+=c*(5*w),T+=f*(5*K),T+=u*(5*b),T+=y*(5*g),x+=T>>>13,T&=8191;let C=x;C+=h*g,C+=r*m,C+=n*d,C+=a*p,C+=o*(5*E),x=C>>>13,C&=8191,C+=l*(5*A),C+=c*(5*_),C+=f*(5*w),C+=u*(5*K),C+=y*(5*b),x+=C>>>13,C&=8191;let O=x;O+=h*b,O+=r*g,O+=n*m,O+=a*d,O+=o*p,x=O>>>13,O&=8191,O+=l*(5*E),O+=c*(5*A),O+=f*(5*_),O+=u*(5*w),O+=y*(5*K),x+=O>>>13,O&=8191;let Y=x;Y+=h*K,Y+=r*b,Y+=n*g,Y+=a*m,Y+=o*d,x=Y>>>13,Y&=8191,Y+=l*p,Y+=c*(5*E),Y+=f*(5*A),Y+=u*(5*_),Y+=y*(5*w),x+=Y>>>13,Y&=8191;let I=x;I+=h*w,I+=r*K,I+=n*b,I+=a*g,I+=o*m,x=I>>>13,I&=8191,I+=l*d,I+=c*p,I+=f*(5*E),I+=u*(5*A),I+=y*(5*_),x+=I>>>13,I&=8191;let z=x;z+=h*_,z+=r*w,z+=n*K,z+=a*b,z+=o*g,x=z>>>13,z&=8191,z+=l*m,z+=c*d,z+=f*p,z+=u*(5*E),z+=y*(5*A),x+=z>>>13,z&=8191;let X=x;X+=h*A,X+=r*_,X+=n*w,X+=a*K,X+=o*b,x=X>>>13,X&=8191,X+=l*g,X+=c*m,X+=f*d,X+=u*p,X+=y*(5*E),x+=X>>>13,X&=8191;let j=x;j+=h*E,j+=r*A,j+=n*_,j+=a*w,j+=o*K,x=j>>>13,j&=8191,j+=l*b,j+=c*g,j+=f*m,j+=u*d,j+=y*p,x+=j>>>13,j&=8191,x=(x<<2)+x|0,x=x+P|0,P=8191&x,x>>>=13,B+=x,h=P,r=B,n=T,a=C,o=O,l=Y,c=I,f=z,u=X,y=j,e+=16,s-=16}this.h[0]=h,this.h[1]=r,this.h[2]=n,this.h[3]=a,this.h[4]=o,this.h[5]=l,this.h[6]=c,this.h[7]=f,this.h[8]=u,this.h[9]=y}finish(t,e){if(this.leftover){let t=this.leftover;for(this.buffer[t++]=1;t<16;t++)this.buffer[t]=0;this.fin=1,this.blocks(this.buffer,0,16)}let s=this.h[1]>>>13;this.h[1]&=8191;for(let t=2;t<10;t++)this.h[t]+=s,s=this.h[t]>>>13,this.h[t]&=8191;this.h[0]+=5*s,s=this.h[0]>>>13,this.h[0]&=8191,this.h[1]+=s,s=this.h[1]>>>13,this.h[1]&=8191,this.h[2]+=s;const i=new Uint16Array(10);i[0]=this.h[0]+5,s=i[0]>>>13,i[0]&=8191;for(let t=1;t<10;t++)i[t]=this.h[t]+s,s=i[t]>>>13,i[t]&=8191;i[9]-=8192;let h=(1^s)-1;for(let t=0;t<10;t++)i[t]&=h;h=~h;for(let t=0;t<10;t++)this.h[t]=this.h[t]&h|i[t];this.h[0]=65535&(this.h[0]|this.h[1]<<13),this.h[1]=65535&(this.h[1]>>>3|this.h[2]<<10),this.h[2]=65535&(this.h[2]>>>6|this.h[3]<<7),this.h[3]=65535&(this.h[3]>>>9|this.h[4]<<4),this.h[4]=65535&(this.h[4]>>>12|this.h[5]<<1|this.h[6]<<14),this.h[5]=65535&(this.h[6]>>>2|this.h[7]<<11),this.h[6]=65535&(this.h[7]>>>5|this.h[8]<<8),this.h[7]=65535&(this.h[8]>>>8|this.h[9]<<5);let r=this.h[0]+this.pad[0];this.h[0]=65535&r;for(let t=1;t<8;t++)r=(this.h[t]+this.pad[t]|0)+(r>>>16)|0,this.h[t]=65535&r;t[e+0]=this.h[0]>>>0&255,t[e+1]=this.h[0]>>>8&255,t[e+2]=this.h[1]>>>0&255,t[e+3]=this.h[1]>>>8&255,t[e+4]=this.h[2]>>>0&255,t[e+5]=this.h[2]>>>8&255,t[e+6]=this.h[3]>>>0&255,t[e+7]=this.h[3]>>>8&255,t[e+8]=this.h[4]>>>0&255,t[e+9]=this.h[4]>>>8&255,t[e+10]=this.h[5]>>>0&255,t[e+11]=this.h[5]>>>8&255,t[e+12]=this.h[6]>>>0&255,t[e+13]=this.h[6]>>>8&255,t[e+14]=this.h[7]>>>0&255,t[e+15]=this.h[7]>>>8&255}update(t,e,s){if(this.leftover){let i=16-this.leftover;i>s&&(i=s);for(let s=0;s<i;s++)this.buffer[this.leftover+s]=t[e+s];if(s-=i,e+=i,this.leftover+=i,this.leftover<16)return;this.blocks(this.buffer,0,16),this.leftover=0}if(s>=16){const i=s-s%16;this.blocks(t,e,i),e+=i,s-=i}if(s){for(let i=0;i<s;i++)this.buffer[this.leftover+i]=t[e+i];this.leftover+=s}}}a.KEYBYTES=32,a.TAGBYTES=16,a.BLOCKBYTES=16;var o=Object.freeze({__proto__:null,Poly1305:a});const l=new Uint8Array(16);function c(t,e){const s=15&e;0!==s&&t.update(l,0,16-s)}function f(t,e,s,i,h,n){const o=new Uint8Array(a.KEYBYTES);r(e,s,o,o,0);const l=new a(o);void 0!==n&&(l.update(n,0,n.byteLength),c(l,n.byteLength)),l.update(i,0,h),c(l,h);const f=new Uint8Array(16),u=new DataView(f.buffer);void 0!==n&&u.setUint32(0,n.byteLength,!0),u.setUint32(8,h,!0),l.update(f,0,f.byteLength),l.finish(t,0)}function u(t,e,s,i,h,n,a){r(h,n,t,e,1,s),f(i,h,n,e,s,a)}function y(t,e,s,i,h,n,a){const o=new Uint8Array(16);f(o,h,n,e,s,a);const l=0===function(t,e,s){let i=0;for(let h=0;h<s;h++)i|=t[h]^e[h];return(1&i-1>>>8)-1}(o,i,o.byteLength);return l?r(h,n,e,t,1,s):t.fill(0,0,s),l}var p=Object.freeze({__proto__:null,AEAD_CHACHA20_POLY1305_KEYBYTES:32,AEAD_CHACHA20_POLY1305_NONCEBYTES:12,AEAD_CHACHA20_POLY1305_TAGBYTES:16,aead_decrypt_detached:y,aead_encrypt_detached:u});function d(t,e){return t>>>e|t<<32-e}function m(t,e,s,i,h,r,n){t[e]=t[e]+t[s]+r,t[h]=d(t[h]^t[e],16),t[i]=t[i]+t[h],t[s]=d(t[s]^t[i],12),t[e]=t[e]+t[s]+n,t[h]=d(t[h]^t[e],8),t[i]=t[i]+t[h],t[s]=d(t[s]^t[i],7)}const g=Uint32Array.from([1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225]),b=Uint8Array.from([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3,11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4,7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8,9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13,2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9,12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11,13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10,6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5,10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]);function K(t,e){return b[(t<<4)+e]}class w{static digest(t,e,s){const i=new w(e,s);return i.update(t),i.final()}constructor(t=w.OUTBYTES,e){var s;this.outlen=t,this.b=new Uint8Array(64),this.bv=new DataView(this.b.buffer),this.h=Uint32Array.from(g),this.t=new Uint32Array(2),this.c=0;const i=null!==(s=null==e?void 0:e.byteLength)&&void 0!==s?s:0;if(0==t||t>32||i>32)throw new Error("illegal BLAKE2s parameter length(s)");this.h[0]^=16842752^i<<8^t,void 0!==e&&i>0&&(this.update(e),this.c=64)}update(t){for(let e=0;e<t.byteLength;e++)64==this.c&&(this.t[0]+=this.c,this.t[0]<this.c&&this.t[1]++,this.compress(!1),this.c=0),this.b[this.c++]=t[e]}final(t){for(this.t[0]+=this.c,this.t[0]<this.c&&this.t[1]++;this.c<64;)this.b[this.c++]=0;this.compress(!0),void 0===t&&(t=new Uint8Array(this.outlen));for(let e=0;e<this.outlen;e++)t[e]=this.h[e>>2]>>8*(3&e)&255;return t}compress(t){const e=new Uint32Array(16),s=new Uint32Array(16);for(let t=0;t<8;t++)e[t]=this.h[t],e[t+8]=g[t];e[12]^=this.t[0],e[13]^=this.t[1],t&&(e[14]=~e[14]);for(let t=0;t<16;t++)s[t]=this.bv.getUint32(t<<2,!0);for(let t=0;t<10;t++)m(e,0,4,8,12,s[K(t,0)],s[K(t,1)]),m(e,1,5,9,13,s[K(t,2)],s[K(t,3)]),m(e,2,6,10,14,s[K(t,4)],s[K(t,5)]),m(e,3,7,11,15,s[K(t,6)],s[K(t,7)]),m(e,0,5,10,15,s[K(t,8)],s[K(t,9)]),m(e,1,6,11,12,s[K(t,10)],s[K(t,11)]),m(e,2,7,8,13,s[K(t,12)],s[K(t,13)]),m(e,3,4,9,14,s[K(t,14)],s[K(t,15)]);for(let t=0;t<8;t++)this.h[t]^=e[t]^e[t+8]}}w.KEYBYTES=32,w.OUTBYTES=32,w.BLOCKLEN=64;var _=Object.freeze({__proto__:null,BLAKE2s:w});class A{constructor(t=0,e=0){this.lo=t,this.hi=e}increment(){const t=this.lo,e=t+1|0;this.lo=e,e<t&&(this.hi=this.hi+1|0)}reset(t=0,e=0){this.lo=t,this.hi=e}static get MAX(){return new A(4294967295,4294967295)}}function E(t,e){const s=Math.min(t.byteLength,e.byteLength),i=new Uint8Array(s);for(let h=0;h<s;h++)i[h]=t[h]^e[h];return i}function U(t,e){const s=new Uint8Array(t.byteLength+e.byteLength);return s.set(t,0),s.set(e,t.byteLength),s}const v=new Uint8Array(0);class M{constructor(t){const e=this.generateKeypair();this.dhlen=this.dh(e,e.public).byteLength,this.hmac=null!=t?t:function(t){const e=new Uint8Array(t.hashBlocklen());e.fill(54);const s=new Uint8Array(t.hashBlocklen());return s.fill(92),(i,h)=>{const r=t._padOrHash(i,t.hashBlocklen());return t.hash(U(E(r,s),t.hash(U(E(r,e),h))))}}(this)}rekey(t){return new DataView(this.encrypt(t,A.MAX,new Uint8Array(32)).buffer)}_padOrHash(t,e){const s=t.byteLength>e?this.hash(t):t;return U(s,new Uint8Array(e-s.byteLength))}hkdf(t,e,s){const i=this.hmac(t,e),h=this.hmac(i,Uint8Array.from([1])),r=this.hmac(i,U(h,Uint8Array.from([2])));switch(s){case 2:return[h,r];case 3:return[h,r,this.hmac(i,U(r,Uint8Array.from([3])))]}}matchingPattern(t){const e=new RegExp(`^Noise_([A-Za-z0-9+]+)_${this.dhName()}_${this.cipherName()}_${this.hashName()}$`).exec(t);return null===e?null:e[1]}}class S{constructor(t,e){this.algorithms=t,this.view=null,this.nonce=new A,void 0!==e&&(this.view=new DataView(e.buffer))}encrypt(t,e){if(null===this.view)return t;const s=this.algorithms.encrypt(this.view,this.nonce,t,e);return this.nonce.increment(),s}decrypt(t,e){if(null===this.view)return t;const s=this.algorithms.decrypt(this.view,this.nonce,t,e);return this.nonce.increment(),s}rekey(){null!==this.view&&(this.view=this.algorithms.rekey(this.view))}}var k=Object.freeze({__proto__:null,CipherState:S,NoiseHandshake:class{constructor(t,e,s,i={}){var h,r,n,a,o;this.algorithms=t,this.pattern=e,this.role=s,this.stepIndex=0,this.staticKeypair=null!==(h=i.staticKeypair)&&void 0!==h?h:this.algorithms.generateKeypair(),this.remoteStaticPublicKey=null!==(r=i.remoteStaticPublicKey)&&void 0!==r?r:null,this.ephemeralKeypair=null!==(n=i.pregeneratedEphemeralKeypair)&&void 0!==n?n:this.algorithms.generateKeypair(),this.remoteEphemeralPublicKey=null!==(a=i.remotePregeneratedEphemeralPublicKey)&&void 0!==a?a:null,this.preSharedKeys=i.preSharedKeys,this.preSharedKeys&&(this.preSharedKeys=this.preSharedKeys.slice(),0===this.preSharedKeys.length&&(this.preSharedKeys=void 0));const l=(new TextEncoder).encode("Noise_"+this.pattern.name+"_"+this.algorithms.dhName()+"_"+this.algorithms.cipherName()+"_"+this.algorithms.hashName());this.cipherState=new S(this.algorithms),this.chainingKey=this.algorithms._padOrHash(l,this.algorithms.hash(v).byteLength),this.handshakeHash=this.chainingKey,this.mixHash(null!==(o=i.prologue)&&void 0!==o?o:v),this.pattern.initiatorPreMessage.forEach((t=>this.mixHash("e"===t?this.isInitiator?this.ephemeralKeypair.public:this.remoteEphemeralPublicKey:this.isInitiator?this.staticKeypair.public:this.remoteStaticPublicKey))),this.pattern.responderPreMessage.forEach((t=>this.mixHash("e"===t?this.isInitiator?this.remoteEphemeralPublicKey:this.ephemeralKeypair.public:this.isInitiator?this.remoteStaticPublicKey:this.staticKeypair.public)))}get isInitiator(){return"initiator"===this.role}mixHash(t){this.handshakeHash=this.algorithms.hash(U(this.handshakeHash,t))}mixKey(t){const[e,s]=this.algorithms.hkdf(this.chainingKey,t,2);this.chainingKey=e,this.cipherState=new S(this.algorithms,s)}mixKeyAndHashNextPSK(){const t=this.preSharedKeys.shift(),[e,s,i]=this.algorithms.hkdf(this.chainingKey,t,3);this.chainingKey=e,this.mixHash(s),this.cipherState=new S(this.algorithms,i)}encryptAndHash(t){const e=this.cipherState.encrypt(t,this.handshakeHash);return this.mixHash(e),e}decryptAndHash(t){const e=this.cipherState.decrypt(t,this.handshakeHash);return this.mixHash(t),e}_split(){if(this.stepIndex<this.pattern.messages.length)return null;{let[t,e]=this.algorithms.hkdf(this.chainingKey,v,2).map((t=>new S(this.algorithms,t)));return this.isInitiator?{send:t,recv:e}:{send:e,recv:t}}}_nextStep(){if(this.stepIndex>=this.pattern.messages.length)throw new Error("Handshake already complete, cannot continue");return this.pattern.messages[this.stepIndex++]}_processKeyMixToken(t){switch(t){case"ee":this.mixKey(this.algorithms.dh(this.ephemeralKeypair,this.remoteEphemeralPublicKey));break;case"es":this.mixKey(this.isInitiator?this.algorithms.dh(this.ephemeralKeypair,this.remoteStaticPublicKey):this.algorithms.dh(this.staticKeypair,this.remoteEphemeralPublicKey));break;case"se":this.mixKey(this.isInitiator?this.algorithms.dh(this.staticKeypair,this.remoteEphemeralPublicKey):this.algorithms.dh(this.ephemeralKeypair,this.remoteStaticPublicKey));break;case"ss":this.mixKey(this.algorithms.dh(this.staticKeypair,this.remoteStaticPublicKey));break;case"psk":this.mixKeyAndHashNextPSK()}}writeMessage(t){const e=[];let s;if(this._nextStep().forEach((t=>{switch(t){case"e":e.push(this.ephemeralKeypair.public),this.mixHash(this.ephemeralKeypair.public),this.preSharedKeys&&this.mixKey(this.ephemeralKeypair.public);break;case"s":e.push(this.encryptAndHash(this.staticKeypair.public));break;default:this._processKeyMixToken(t)}})),e.push(this.encryptAndHash(t)),1===e.length)s=e[0];else{s=new Uint8Array(e.reduce(((t,e)=>t+e.byteLength),0));let t=0;e.forEach((e=>{s.set(e,t),t+=e.byteLength}))}return{packet:s,finished:this._split()}}readMessage(t){const e=e=>{const s=t.slice(0,e);return t=t.subarray(e),s};this._nextStep().forEach((t=>{switch(t){case"e":this.remoteEphemeralPublicKey=e(this.algorithms.dhlen),this.mixHash(this.remoteEphemeralPublicKey),this.preSharedKeys&&this.mixKey(this.remoteEphemeralPublicKey);break;case"s":this.remoteStaticPublicKey=this.decryptAndHash(e(this.algorithms.dhlen+(this.cipherState.view?16:0)));break;default:this._processKeyMixToken(t)}}));return{message:this.decryptAndHash(t),finished:this._split()}}async completeHandshake(t,e,s=(async t=>{}),i=(async()=>new Uint8Array(0))){const h=async()=>{const{packet:e,finished:s}=this.writeMessage(await i());return await t(e),s||r()},r=async()=>{const{message:t,finished:i}=this.readMessage(await e());return await s(t),i||h()};return this.isInitiator?h():r()}},NoiseProtocolAlgorithms:M,Nonce:A,bytesAppend:U,bytesXor:E});const L={};function H(t,e,s,i){const h={name:t,baseName:t,messages:e,initiatorPreMessage:s,responderPreMessage:i};L[h.name]=h}H("N",[["e","es"]],[],["s"]),H("K",[["e","es","ss"]],["s"],["s"]),H("X",[["e","es","s","ss"]],[],["s"]),H("NN",[["e"],["e","ee"]],[],[]),H("NK",[["e","es"],["e","ee"]],[],["s"]),H("NX",[["e"],["e","ee","s","es"]],[],[]),H("KN",[["e"],["e","ee","se"]],["s"],[]),H("KK",[["e","es","ss"],["e","ee","se"]],["s"],["s"]),H("KX",[["e"],["e","ee","se","s","es"]],["s"],[]),H("XN",[["e"],["e","ee"],["s","se"]],[],[]),H("XK",[["e","es"],["e","ee"],["s","se"]],[],["s"]),H("XX",[["e"],["e","ee","s","es"],["s","se"]],[],[]),H("IN",[["e","s"],["e","ee","se"]],[],[]),H("IK",[["e","es","s","ss"],["e","ee","se"]],[],["s"]),H("IX",[["e","s"],["e","ee","se","s","es"]],[],[]);const N=/^([NKX]|[NKXI]1?[NKX]1?)([a-z][a-z0-9]*(\+[a-z][a-z0-9]*)*)?$/,x=/^psk([0-9]+)$/;var P=Object.freeze({__proto__:null,PATTERNS:L,isOneWay:function(t){return 1===t.baseName.length},lookupPattern:function(t){var e,s,i;const h=N.exec(t);if(null===h)return null;const r=null!==(s=null===(e=h[2])||void 0===e?void 0:e.split("+"))&&void 0!==s?s:[];let n=null!==(i=L[h[1]])&&void 0!==i?i:null;return n?(r.forEach((t=>n=n&&function(t,e){const s=x.exec(e);if(null===s)return null;const i=parseInt(s[1],10),h=t.messages;return Object.assign(Object.assign({},t),{messages:0===i?[["psk",...h[0]],...h.slice(1)]:[...h.slice(0,i-1),[...h[i-1],"psk"],...h.slice(i)]})}(n,t))),n&&Object.assign(Object.assign({},n),{name:t})):null}});const B=(()=>{var t="undefined"!=typeof self?self.crypto||self.msCrypto:null;if(t&&t.getRandomValues){const e=65536;return(s,i)=>{for(let h=0;h<i;h+=e)t.getRandomValues(s.subarray(h,h+Math.min(i-h,e)))}}if("undefined"!=typeof require&&(t=require("crypto"))&&t.randomBytes)return(e,s)=>e.set(t.randomBytes(s));throw new Error("No usable randomness source found")})();function T(t){const e=new Uint8Array(t);return B(e,t),e}var C=Object.freeze({__proto__:null,_randomBytes:B,randomBytes:T});function O(){return new Float64Array(16)}const Y=new Uint8Array(32);Y[0]=9;const I=O();function z(t){let e=1;for(let s=0;s<16;s++){const i=t[s]+e+65535;e=Math.floor(i/65536),t[s]=i-65536*e}t[0]+=e-1+37*(e-1)}function X(t,e,s){const i=~(s-1);for(let s=0;s<16;s++){const h=i&(t[s]^e[s]);t[s]^=h,e[s]^=h}}function j(t,e,s){for(let i=0;i<16;i++)t[i]=e[i]+s[i]}function D(t,e,s){for(let i=0;i<16;i++)t[i]=e[i]-s[i]}function V(t,e,s){let i=0,h=0,r=0,n=0,a=0,o=0,l=0,c=0,f=0,u=0,y=0,p=0,d=0,m=0,g=0,b=0,K=0,w=0,_=0,A=0,E=0,U=0,v=0,M=0,S=0,k=0,L=0,H=0,N=0,x=0,P=0;const B=s[0],T=s[1],C=s[2],O=s[3],Y=s[4],I=s[5],z=s[6],X=s[7],j=s[8],D=s[9],V=s[10],R=s[11],$=s[12],q=s[13],G=s[14],F=s[15];let W=e[0];i+=W*B,h+=W*T,r+=W*C,n+=W*O,a+=W*Y,o+=W*I,l+=W*z,c+=W*X,f+=W*j,u+=W*D,y+=W*V,p+=W*R,d+=W*$,m+=W*q,g+=W*G,b+=W*F,W=e[1],h+=W*B,r+=W*T,n+=W*C,a+=W*O,o+=W*Y,l+=W*I,c+=W*z,f+=W*X,u+=W*j,y+=W*D,p+=W*V,d+=W*R,m+=W*$,g+=W*q,b+=W*G,K+=W*F,W=e[2],r+=W*B,n+=W*T,a+=W*C,o+=W*O,l+=W*Y,c+=W*I,f+=W*z,u+=W*X,y+=W*j,p+=W*D,d+=W*V,m+=W*R,g+=W*$,b+=W*q,K+=W*G,w+=W*F,W=e[3],n+=W*B,a+=W*T,o+=W*C,l+=W*O,c+=W*Y,f+=W*I,u+=W*z,y+=W*X,p+=W*j,d+=W*D,m+=W*V,g+=W*R,b+=W*$,K+=W*q,w+=W*G,_+=W*F,W=e[4],a+=W*B,o+=W*T,l+=W*C,c+=W*O,f+=W*Y,u+=W*I,y+=W*z,p+=W*X,d+=W*j,m+=W*D,g+=W*V,b+=W*R,K+=W*$,w+=W*q,_+=W*G,A+=W*F,W=e[5],o+=W*B,l+=W*T,c+=W*C,f+=W*O,u+=W*Y,y+=W*I,p+=W*z,d+=W*X,m+=W*j,g+=W*D,b+=W*V,K+=W*R,w+=W*$,_+=W*q,A+=W*G,E+=W*F,W=e[6],l+=W*B,c+=W*T,f+=W*C,u+=W*O,y+=W*Y,p+=W*I,d+=W*z,m+=W*X,g+=W*j,b+=W*D,K+=W*V,w+=W*R,_+=W*$,A+=W*q,E+=W*G,U+=W*F,W=e[7],c+=W*B,f+=W*T,u+=W*C,y+=W*O,p+=W*Y,d+=W*I,m+=W*z,g+=W*X,b+=W*j,K+=W*D,w+=W*V,_+=W*R,A+=W*$,E+=W*q,U+=W*G,v+=W*F,W=e[8],f+=W*B,u+=W*T,y+=W*C,p+=W*O,d+=W*Y,m+=W*I,g+=W*z,b+=W*X,K+=W*j,w+=W*D,_+=W*V,A+=W*R,E+=W*$,U+=W*q,v+=W*G,M+=W*F,W=e[9],u+=W*B,y+=W*T,p+=W*C,d+=W*O,m+=W*Y,g+=W*I,b+=W*z,K+=W*X,w+=W*j,_+=W*D,A+=W*V,E+=W*R,U+=W*$,v+=W*q,M+=W*G,S+=W*F,W=e[10],y+=W*B,p+=W*T,d+=W*C,m+=W*O,g+=W*Y,b+=W*I,K+=W*z,w+=W*X,_+=W*j,A+=W*D,E+=W*V,U+=W*R,v+=W*$,M+=W*q,S+=W*G,k+=W*F,W=e[11],p+=W*B,d+=W*T,m+=W*C,g+=W*O,b+=W*Y,K+=W*I,w+=W*z,_+=W*X,A+=W*j,E+=W*D,U+=W*V,v+=W*R,M+=W*$,S+=W*q,k+=W*G,L+=W*F,W=e[12],d+=W*B,m+=W*T,g+=W*C,b+=W*O,K+=W*Y,w+=W*I,_+=W*z,A+=W*X,E+=W*j,U+=W*D,v+=W*V,M+=W*R,S+=W*$,k+=W*q,L+=W*G,H+=W*F,W=e[13],m+=W*B,g+=W*T,b+=W*C,K+=W*O,w+=W*Y,_+=W*I,A+=W*z,E+=W*X,U+=W*j,v+=W*D,M+=W*V,S+=W*R,k+=W*$,L+=W*q,H+=W*G,N+=W*F,W=e[14],g+=W*B,b+=W*T,K+=W*C,w+=W*O,_+=W*Y,A+=W*I,E+=W*z,U+=W*X,v+=W*j,M+=W*D,S+=W*V,k+=W*R,L+=W*$,H+=W*q,N+=W*G,x+=W*F,W=e[15],b+=W*B,K+=W*T,w+=W*C,_+=W*O,A+=W*Y,E+=W*I,U+=W*z,v+=W*X,M+=W*j,S+=W*D,k+=W*V,L+=W*R,H+=W*$,N+=W*q,x+=W*G,P+=W*F,i+=38*K,h+=38*w,r+=38*_,n+=38*A,a+=38*E,o+=38*U,l+=38*v,c+=38*M,f+=38*S,u+=38*k,y+=38*L,p+=38*H,d+=38*N,m+=38*x,g+=38*P;let Z=1;W=i+Z+65535,Z=Math.floor(W/65536),i=W-65536*Z,W=h+Z+65535,Z=Math.floor(W/65536),h=W-65536*Z,W=r+Z+65535,Z=Math.floor(W/65536),r=W-65536*Z,W=n+Z+65535,Z=Math.floor(W/65536),n=W-65536*Z,W=a+Z+65535,Z=Math.floor(W/65536),a=W-65536*Z,W=o+Z+65535,Z=Math.floor(W/65536),o=W-65536*Z,W=l+Z+65535,Z=Math.floor(W/65536),l=W-65536*Z,W=c+Z+65535,Z=Math.floor(W/65536),c=W-65536*Z,W=f+Z+65535,Z=Math.floor(W/65536),f=W-65536*Z,W=u+Z+65535,Z=Math.floor(W/65536),u=W-65536*Z,W=y+Z+65535,Z=Math.floor(W/65536),y=W-65536*Z,W=p+Z+65535,Z=Math.floor(W/65536),p=W-65536*Z,W=d+Z+65535,Z=Math.floor(W/65536),d=W-65536*Z,W=m+Z+65535,Z=Math.floor(W/65536),m=W-65536*Z,W=g+Z+65535,Z=Math.floor(W/65536),g=W-65536*Z,W=b+Z+65535,Z=Math.floor(W/65536),b=W-65536*Z,i+=Z-1+37*(Z-1),Z=1,W=i+Z+65535,Z=Math.floor(W/65536),i=W-65536*Z,W=h+Z+65535,Z=Math.floor(W/65536),h=W-65536*Z,W=r+Z+65535,Z=Math.floor(W/65536),r=W-65536*Z,W=n+Z+65535,Z=Math.floor(W/65536),n=W-65536*Z,W=a+Z+65535,Z=Math.floor(W/65536),a=W-65536*Z,W=o+Z+65535,Z=Math.floor(W/65536),o=W-65536*Z,W=l+Z+65535,Z=Math.floor(W/65536),l=W-65536*Z,W=c+Z+65535,Z=Math.floor(W/65536),c=W-65536*Z,W=f+Z+65535,Z=Math.floor(W/65536),f=W-65536*Z,W=u+Z+65535,Z=Math.floor(W/65536),u=W-65536*Z,W=y+Z+65535,Z=Math.floor(W/65536),y=W-65536*Z,W=p+Z+65535,Z=Math.floor(W/65536),p=W-65536*Z,W=d+Z+65535,Z=Math.floor(W/65536),d=W-65536*Z,W=m+Z+65535,Z=Math.floor(W/65536),m=W-65536*Z,W=g+Z+65535,Z=Math.floor(W/65536),g=W-65536*Z,W=b+Z+65535,Z=Math.floor(W/65536),b=W-65536*Z,i+=Z-1+37*(Z-1),t[0]=i,t[1]=h,t[2]=r,t[3]=n,t[4]=a,t[5]=o,t[6]=l,t[7]=c,t[8]=f,t[9]=u,t[10]=y,t[11]=p,t[12]=d,t[13]=m,t[14]=g,t[15]=b}function R(t,e){V(t,e,e)}function $(t,e,s){const i=new Uint8Array(32),h=new Float64Array(80),r=O(),n=O(),a=O(),o=O(),l=O(),c=O();for(let t=0;t<31;t++)i[t]=e[t];i[31]=127&e[31]|64,i[0]&=248,function(t,e){for(let s=0;s<16;s++)t[s]=e[2*s]+(e[2*s+1]<<8);t[15]&=32767}(h,s);for(let t=0;t<16;t++)n[t]=h[t],o[t]=r[t]=a[t]=0;r[0]=o[0]=1;for(let t=254;t>=0;--t){const e=i[t>>>3]>>>(7&t)&1;X(r,n,e),X(a,o,e),j(l,r,a),D(r,r,a),j(a,n,o),D(n,n,o),R(o,l),R(c,r),V(r,a,r),V(a,n,l),j(l,r,a),D(r,r,a),R(n,r),D(a,o,c),V(r,a,I),j(r,r,o),V(a,a,r),V(r,o,c),V(o,n,h),R(n,l),X(r,n,e),X(a,o,e)}for(let t=0;t<16;t++)h[t+16]=r[t],h[t+32]=a[t],h[t+48]=n[t],h[t+64]=o[t];const f=h.subarray(32),u=h.subarray(16);!function(t,e){const s=O();for(let t=0;t<16;t++)s[t]=e[t];for(let t=253;t>=0;t--)R(s,s),2!==t&&4!==t&&V(s,s,e);for(let e=0;e<16;e++)t[e]=s[e]}(f,f),V(u,u,f),function(t,e){const s=O(),i=O();for(let t=0;t<16;t++)i[t]=e[t];z(i),z(i),z(i);for(let t=0;t<2;t++){s[0]=i[0]-65517;for(let t=1;t<15;t++)s[t]=i[t]-65535-(s[t-1]>>16&1),s[t-1]&=65535;s[15]=i[15]-32767-(s[14]>>16&1);const t=s[15]>>16&1;s[14]&=65535,X(i,s,1-t)}for(let e=0;e<16;e++)t[2*e]=255&i[e],t[2*e+1]=i[e]>>8}(t,u)}function q(t,e){$(t,e,Y)}function G(t,e){if(32!==t.length)throw new Error("bad n size");if(32!==e.length)throw new Error("bad p size");const s=new Uint8Array(32);return $(s,t,e),s}function F(t){if(32!==t.length)throw new Error("bad n size");const e=new Uint8Array(32);return q(e,t),e}I[0]=56129,I[1]=1,G.scalarLength=32,G.groupElementLength=32;var W=Object.freeze({__proto__:null,crypto_scalarmult:$,crypto_scalarmult_BYTES:32,crypto_scalarmult_SCALARBYTES:32,crypto_scalarmult_base:q,scalarMult:G,scalarMultBase:F});function Z(t){const e=new DataView(new ArrayBuffer(12));return e.setUint32(4,t.lo,!0),e.setUint32(8,t.hi,!0),e}var J=Object.freeze({__proto__:null,Noise_25519_ChaChaPoly_BLAKE2s:class extends M{constructor(){super()}dhName(){return"25519"}generateKeypair(){const t=T(G.scalarLength);return{public:F(t),secret:t}}dh(t,e){return G(t.secret,e)}cipherName(){return"ChaChaPoly"}encrypt(t,e,s,i){const h=new Uint8Array(s.byteLength+16);return u(s,h,s.byteLength,h.subarray(s.byteLength),t,Z(e),i),h}decrypt(t,e,s,i){const h=new Uint8Array(s.byteLength-16);if(!y(h,s,h.byteLength,s.subarray(h.byteLength),t,Z(e),i))throw new Error("packet decryption failed");return h}hashName(){return"BLAKE2s"}hash(t){return w.digest(t)}hashBlocklen(){return w.BLOCKLEN}}});t.AEAD=p,t.BLAKE2=_,t.ChaCha20=n,t.Noise=k,t.NoiseProfiles=J,t.Patterns=P,t.Poly1305=o,t.Random=C,t.X25519=W}));
