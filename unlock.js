const form=document.getElementById('unlock-form'),input=document.getElementById('password'),message=document.getElementById('message'),submit=document.getElementById('unlock-button');
const configuration={"algorithm":"AES-GCM","kdf":"PBKDF2-SHA256","iterations":600000,"salt":"whBqkecC7phpEKBGM7Eksw==","iv":"Syho6xQbnOmMu/rb"};
const fromBase64=value=>Uint8Array.from(atob(value),character=>character.charCodeAt(0));
let cachedCipher;
const objectUrls=[];
async function unlock(event){
 event.preventDefault();message.textContent='암호를 확인하고 있습니다.';submit.disabled=true;
 try{
  if(!crypto.subtle)throw new Error('HTTPS 주소에서 열어 주세요.');
  const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(input.value),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:fromBase64(configuration.salt),iterations:configuration.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
  if(!cachedCipher){const response=await fetch('./content.bin',{cache:'no-store'});if(!response.ok)throw new Error('페이지 자료를 불러오지 못했습니다. 잠시 뒤 다시 시도해 주세요.');cachedCipher=await response.arrayBuffer();}
  let clear;try{clear=await crypto.subtle.decrypt({name:'AES-GCM',iv:fromBase64(configuration.iv)},key,cachedCipher);}catch{message.textContent='암호가 맞지 않습니다. 다시 입력해 주세요.';input.focus();input.select();return;}
  const view=new Uint8Array(clear),length=new DataView(clear).getUint32(0,false);
  if(length>1000000||length+4>view.length)throw new Error('페이지 자료 형식이 올바르지 않습니다.');
  const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(view.subarray(4,4+length))),start=4+length;
  if(!Array.isArray(manifest.files))throw new Error('페이지 자료 형식이 올바르지 않습니다.');
  const files=new Map(),assets={};
  for(const file of manifest.files){
   if(!Number.isSafeInteger(file.offset)||!Number.isSafeInteger(file.length)||file.offset<0||file.length<0||start+file.offset+file.length>view.length)throw new Error('페이지 자료 형식이 올바르지 않습니다.');
   files.set(file.path,{...file,data:view.subarray(start+file.offset,start+file.offset+file.length)});
  }
  for(const [name,file] of files)if(name.startsWith('assets/')){const url=URL.createObjectURL(new Blob([file.data],{type:file.type}));assets['/'+name]=url;objectUrls.push(url);}
  globalThis.__WESCO_ASSETS__=assets;
  const cssFile=files.get('reader.css'),jsFile=files.get('reader.js');
  if(!cssFile||!jsFile)throw new Error('필요한 페이지 자료가 없습니다.');
  let css=new TextDecoder().decode(cssFile.data);
  css=css.replace(/url\(\s*(['"]?)(\/assets\/[^'")]+)\1\s*\)/g,(_,quote,path)=>{if(!assets[path])throw new Error('필요한 글꼴 자료가 없습니다.');return 'url("'+assets[path]+'")';});
  const style=document.createElement('style');style.textContent=css;document.head.append(style);
  input.value='';cachedCipher=null;
  document.getElementById('root').replaceChildren();
  const scriptUrl=URL.createObjectURL(new Blob([jsFile.data],{type:'text/javascript'}));objectUrls.push(scriptUrl);
  const script=document.createElement('script');script.src=scriptUrl;script.onerror=()=>{document.getElementById('root').textContent='페이지를 열지 못했습니다. 새로고침 후 다시 입력해 주세요.';};document.body.append(script);
  document.title='Wesco 원고';
 }catch(error){message.textContent=error.message||'페이지를 열지 못했습니다.';}finally{submit.disabled=false;}
}
form.addEventListener('submit',unlock);
window.addEventListener('pagehide',event=>{if(!event.persisted)for(const url of objectUrls)URL.revokeObjectURL(url);});

