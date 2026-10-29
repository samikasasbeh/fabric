const requestId=new URL(location.href).searchParams.get('request');
const status=document.querySelector('#status'),approve=document.querySelector('#approve'),cancel=document.querySelector('#cancel');
let request,working=false,paired=false;
const show=(message,error=false)=>{status.textContent=message;status.classList.toggle('error',error);};
async function initialize(){
  try {
    const response=await chrome.runtime.sendMessage({type:'fabric-connect-details',requestId});
    if(!response?.ok) throw new Error(response?.error||'Connection request expired. Return to Fabric and try again.');
    request=response.request;
    document.querySelector('#app-name').textContent=request.appName;
    document.querySelector('#app-origin').textContent=request.origin;
    approve.disabled=false;
  }catch(error){show(error.message,true);}
}
approve.addEventListener('click',async()=>{
  if(!request||working||paired) return;
  working=true;approve.disabled=true;cancel.disabled=true;
  try {
    // Chrome requires the optional website-permission prompt to originate from
    // this explicit extension-page button, not a background automation request.
    const granted=await chrome.permissions.request({origins:[`${request.origin}/*`]});
    if(!granted) throw new Error('Website access was not approved. Nothing was connected.');
    show('Saving your browser connection, then opening the app for sign-in…');
    const response=await chrome.runtime.sendMessage({type:'fabric-connect-approve',requestId});
    if(!response?.ok) throw new Error(response?.error||'Connection could not be completed.');
    paired=true;
    show(`Connection saved in this browser profile. Account sign-in is not verified. ${response.signInOpened===false?'The sign-in tab could not open; open the website in this browser yourself.':'Sign in on the app website if needed.'} You can close app tabs. Fabric opens a tab only when needed for an approved read; clicks and fills still require a fresh inspection and exact approval.`);
    approve.textContent='Connection saved';
    cancel.textContent='Close this setup page';
  }catch(error){show(error.message,true);approve.disabled=false;}
  finally{working=false;cancel.disabled=false;}
});
cancel.addEventListener('click',async()=>{
  if(working)return;
  if(paired){window.close();return;}
  try {
    const response=await chrome.runtime.sendMessage({type:'fabric-connect-cancel',requestId});
    if(!response?.ok)throw new Error(response?.error||'Could not cancel this request.');
    window.close();
  }catch(error){show(error.message,true);}
});
initialize();
