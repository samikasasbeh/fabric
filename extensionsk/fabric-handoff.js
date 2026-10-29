// This bridge carries setup requests only. Browser credentials and page data never
// cross window.postMessage; operation execution stays in the authenticated queue.
(() => {
  const origin='http://127.0.0.1:4188';
  if(location.origin!==origin||window.top!==window) return;
  window.addEventListener('message',async event=>{
    const message=event.data;
    if(event.source!==window||event.origin!==origin||!message||message.source!=='fabric-page'||!['fabric:bridge:ping','fabric:bridge:connect'].includes(message.type)||typeof message.requestId!=='string'||!/^[a-zA-Z0-9-]{1,100}$/.test(message.requestId)) return;
    const reply={source:'fabric-extension',type:'fabric:bridge:result',requestId:message.requestId};
    try {
      if(message.type==='fabric:bridge:ping') {window.postMessage({...reply,ok:true,version:'0.3'},origin);return;}
      const result=await chrome.runtime.sendMessage({type:'fabric-connect-request',pairing:message.pairing});
      window.postMessage({...reply,...result},origin);
    } catch(error) {window.postMessage({...reply,ok:false,error:'Fabric helper is unavailable. Reload this Fabric page after installing or updating the extension.'},origin);}
  });
})();
