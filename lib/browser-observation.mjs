// This function is serialized by Playwright and runs in the approved page. It
// has no closure, performs no actions, and never reads form values or storage.
export function observeBrowserPage({op,selector,expectedOrigin}) {
  if(location.origin!==expectedOrigin)throw new Error('The page origin changed.');
  if(!['observe','read'].includes(op))throw new Error('Only read-only browser observation is supported.');
  const visible=element=>{
    if(!element?.isConnected||!element.getClientRects().length)return false;
    for(let current=element;current;current=current.parentElement){const style=getComputedStyle(current);if(current.hidden||current.getAttribute('aria-hidden')==='true'||style.display==='none'||['hidden','collapse'].includes(style.visibility)||style.opacity==='0')return false;}
    return true;
  };
  const privateElement=element=>Boolean(element.closest('input,textarea,select,[contenteditable]:not([contenteditable="false"]),[data-sensitive],script,style,[hidden],[aria-hidden="true"]'));
  const sensitive=element=>/password|passwd|secret|(?:access|refresh|auth)[-_ ]?token|api[-_ ]?key|private[-_ ]?key|credit|card.?number|cc-|cvc|cvv|security.?code|one.?time|otp|ssn|social.?security|bank.?account|routing.?number|recovery.?code|verification.?code/i.test([element.getAttribute('autocomplete'),element.getAttribute('name'),element.id,element.getAttribute('type'),element.getAttribute('aria-label')].join(' '));
  const text=element=>{
    if(!element)return '';
    const walker=document.createTreeWalker(element,NodeFilter.SHOW_TEXT);let output='',count=0,node;
    while((node=walker.nextNode())&&count++<5000&&output.length<24000){const parent=node.parentElement;if(parent&&!privateElement(parent)&&!sensitive(parent)&&visible(parent))output+=`${node.textContent.trim()} `;}
    return output.trim().slice(0,24000);
  };
  let root=document.body;
  if(op==='read'){
    if(typeof selector!=='string'||!selector.trim()||selector.length>500)throw new Error('A bounded element selector is required.');
    const matches=document.querySelectorAll(selector);
    if(matches.length!==1||!visible(matches[0])||privateElement(matches[0])||sensitive(matches[0]))throw new Error('Select one visible, non-sensitive element.');
    root=matches[0];
  }
  const controls=[];
  if(op==='observe'){
    let visited=0;
    for(const element of document.querySelectorAll('button,a,[role="button"],[role="tab"]')){
      if(++visited>5000||controls.length>=100)break;
      if(!visible(element)||privateElement(element)||sensitive(element))continue;
      controls.push({role:element.getAttribute('role')||element.tagName.toLowerCase(),label:(element.getAttribute('aria-label')||text(element)).trim().slice(0,120),selector:element.id?`#${CSS.escape(element.id)}`:null,canClick:false,canFill:false});
    }
  }
  if(location.origin!==expectedOrigin)throw new Error('The page origin changed.');
  return {origin:location.origin,title:document.title.slice(0,160),text:text(root),...(op==='observe'?{controls}:{selector}),accountBinding:'Dedicated Fabric browser profile; provider account identity is not verified.'};
}
