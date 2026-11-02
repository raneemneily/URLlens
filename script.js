const BRANDS = ["paypal","google","microsoft","apple","amazon","facebook","instagram","netflix","binance","steam","whatsapp","linkedin","github","outlook","dropbox","poste","attijari","biat","ooredoo","orange"];
const BAD_TLD = ["xyz","top","zip","click","work","gq","tk","ml","cf","ga","icu","buzz","rest"];
const KEYWORDS = ["login","signin","verify","secure","update","account","confirm","password","wallet","bank"];

function lev(a,b){const m=[];for(let i=0;i<=a.length;i++){m[i]=[i];}for(let j=1;j<=b.length;j++)m[0][j]=j;
  for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++)
    m[i][j]=Math.min(m[i-1][j]+1,m[i][j-1]+1,m[i-1][j-1]+(a[i-1]===b[j-1]?0:1));
  return m[a.length][b.length];}
const unleet = s => s.replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e').replace(/5/g,'s').replace(/\$/g,'s');

function analyze(raw){
  const hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  let u; try{ u = new URL(hadScheme ? raw : 'https://'+raw); }catch{ return null; }
  const host = u.hostname.toLowerCase();
  const labels = host.split('.');
  const reg = labels.slice(-2).join('.');
  const regName = labels.length>1 ? labels[labels.length-2] : labels[0];
  const tld = labels[labels.length-1];
  const subs = labels.slice(0,-2);
  const rest = (u.pathname+u.search).toLowerCase();
  const F = [];
  const add=(w,t,y)=>F.push({w,t,y});

  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  if(isIP) add(25,"IP address as host","Real services use domain names. A raw IP often points to a throwaway server.");
  if(u.username || u.password) add(25,"@ symbol hides the real host","Browsers ignore everything before @, so the text you see first is not where the link goes.");
  if(host.includes('xn--')) add(30,"Punycode domain","This host may use look-alike Unicode characters to imitate a trusted name.");
  if(hadScheme && u.protocol==='http:') add(10,"No HTTPS","Traffic and any password you type can be read or changed on the way.");
  if(!isIP && BAD_TLD.includes(tld)) add(15,"Cheap TLD (."+tld+")","This ending is cheap or free and shows up often in abuse reports.");
  if(subs.length>=3) add(10,"Many subdomains ("+subs.length+")","Long subdomain chains push the real domain out of view.");
  if((host.match(/-/g)||[]).length>=3) add(8,"Hyphen-heavy host","Phishing hosts often chain words like secure-login-account-verify.");
  if(raw.length>75) add(5,"Very long URL ("+raw.length+" chars)","Length can hide the suspicious part from a quick glance.");

  if(!isIP){
    const parts = host.split(/[.\-]/).filter(Boolean);
    let hit=null;
    for(const b of BRANDS){
      if(regName===b) continue;
      const cand=[regName,...regName.split('-')];
      for(const c of cand){
        if(c.length<4) continue;
        const n=unleet(c);
        if((n===b && c!==b) || (c!==b && lev(c,b)<=2 && Math.abs(c.length-b.length)<=2 && c[0]===b[0])){hit=[b,c];break;}
      }
      if(hit)break;
    }
    if(hit) add(35,"Possible typosquat of “"+hit[0]+"”","“"+hit[1]+"” looks like “"+hit[0]+"” but is not the real domain.");
    else{
      const wrong = BRANDS.find(b=>parts.includes(b) && regName!==b);
      if(wrong) add(30,"“"+wrong+"” in the wrong place","The real domain is "+reg+", not "+wrong+".com. Brand names in subdomains are a classic trick.");
    }
  }
  const kwHost = KEYWORDS.filter(k=>host.includes(k));
  const kwPath = KEYWORDS.filter(k=>rest.includes(k));
  if(kwHost.length) add(15,"Credential keywords in host: "+kwHost.join(", "),"Legitimate sites rarely put words like these in their domain name.");
  else if(kwPath.length) add(10,"Credential keywords in path: "+kwPath.join(", "),"On its own this is common, but it adds weight to other signals.");

  const score = Math.min(100, F.reduce((s,f)=>s+f.w,0));
  return {score,F,host,reg,isIP};
}

const $=id=>document.getElementById(id);
function show(r){
  const res=$('result'); res.style.display='block';
  const lvl = r.score<25?['Looks safe','var(--ok)']:r.score<55?['Suspicious','var(--warn)']:['Likely phishing','var(--bad)'];
  $('verdict').textContent=lvl[0]; $('verdict').style.color=lvl[1];
  $('score').textContent='risk '+r.score+' / 100';
  $('fill').style.background=lvl[1];
  $('fill').style.width='0'; requestAnimationFrame(()=>requestAnimationFrame(()=>{$('fill').style.width=Math.max(r.score,3)+'%';}));
  $('host').innerHTML=''; const l=document.createElement('span'); l.textContent='Real domain: '; const b=document.createElement('b'); b.textContent=r.isIP?r.host:r.reg; $('host').append(l,b);
  const box=$('finds'); box.innerHTML='';
  r.F.sort((a,b)=>b.w-a.w).forEach(f=>{
    const d=document.createElement('div'); d.className='find';
    const w=document.createElement('div'); w.className='w'; w.textContent='+'+f.w;
    const c=document.createElement('div'); const h=document.createElement('h3'); h.textContent=f.t; const p=document.createElement('p'); p.textContent=f.y;
    c.append(h,p); d.append(w,c); box.append(d);
  });
  $('clean').textContent = r.F.length ? '' : 'No warning signs found in the text of this URL. That does not guarantee the site is safe.';
  res.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'nearest'});
}
$('form').addEventListener('submit',e=>{
  e.preventDefault();
  const v=$('url').value.trim(); if(!v) return;
  const r=analyze(v);
  if(!r){ $('url').setCustomValidity('That does not look like a URL'); $('url').reportValidity(); $('url').setCustomValidity(''); return; }
  show(r);
});
document.querySelectorAll('.samples button').forEach(b=>b.addEventListener('click',()=>{
  $('url').value=b.dataset.u; $('form').requestSubmit();
}));
