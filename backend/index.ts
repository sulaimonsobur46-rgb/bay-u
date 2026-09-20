import { router, json, error } from '@appdeploy/sdk';
import { db, secrets } from '@appdeploy/sdk';
import crypto from 'node:crypto';

type User = { id?:string; name:string; email:string; phone:string; passwordHash:string; verified:boolean; verificationHash?:string; verificationExpires?:number; pinHash:string; balance:number; createdAt:number; };
type Tx = { userId:string; title:string; subtitle:string; amount:number; incoming?:boolean; createdAt:number; counterparty?:string; demoReference?:string; demoSenderId?:string; demoRecipientId?:string; demoSenderName?:string; demoRecipientName?:string; };
type DemoTransfer = { reference:string; senderId:string; recipientId:string; amount:number; createdAt:number; senderName:string; recipientName:string; };

const hash = (v:string) => crypto.createHash('sha256').update(v).digest('hex');
const normalizePhone = (v:string) => v.replace(/[^0-9+]/g,'');
const normalizeEmail = (v:string) => v.trim().toLowerCase();
const publicUser = (u:User, id:string) => ({ id, name:u.name, email:u.email, phone:u.phone, verified:u.verified, balance:u.balance });
async function sendVerification(email:string, code:string) {
  const key = await secrets.readSecret('RESEND_API_KEY');
  const res = await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+key,'Content-Type':'application/json'},body:JSON.stringify({from:'Bay U <onboarding@resend.dev>',to:[email],subject:'Your Bay U verification code',html:'<div style="font-family:Arial,sans-serif"><h2>Verify your Bay U account</h2><p>Your verification code is:</p><p style="font-size:32px;font-weight:700;letter-spacing:8px">'+code+'</p><p>This code expires in 10 minutes.</p></div>'})});
  if(!res.ok) throw new Error('Verification email could not be sent');
}
async function findUser(identifier:string) {
  const q=identifier.includes('@')?normalizeEmail(identifier):normalizePhone(identifier);
  const {items}=await db.list<User>('users',{limit:100});
  return items.find(u=>normalizeEmail(u.email)===q || normalizePhone(u.phone)===q);
}
async function txs(userId:string) {
  const {items}=await db.list<Tx>('transactions',{limit:1000});
  return items.filter(t=>t.userId===userId).sort((a,b)=>b.createdAt-a.createdAt);
}
async function demoTransfers(userId:string) {
  const {items}=await db.list<Tx>('transactions',{limit:1000});
  const seen=new Set<string>(); const out:DemoTransfer[]=[];
  for(const t of items){ if(!t.demoReference || seen.has(t.demoReference)) continue; if(t.demoSenderId!==userId && t.demoRecipientId!==userId) continue; seen.add(t.demoReference); out.push({reference:t.demoReference,senderId:t.demoSenderId||'',recipientId:t.demoRecipientId||'',amount:Number(t.amount)||0,createdAt:t.createdAt,senderName:t.demoSenderName||'',recipientName:t.demoRecipientName||''}); }
  return out.sort((a,b)=>b.createdAt-a.createdAt);
}
function demoBalance(base:number, userId:string, transfers:DemoTransfer[]) {
  return transfers.reduce((balance,t)=>balance+(t.recipientId===userId?t.amount:t.senderId===userId?-t.amount:0),base);
}
function demoHistory(userId:string, transfers:DemoTransfer[]):Tx[] {
  return transfers.map(t=>t.senderId===userId
    ? {id:t.reference,title:'Transfer to '+t.recipientName,subtitle:'Sent to '+t.recipientName+' • Demo',amount:t.amount,incoming:false,createdAt:t.createdAt,counterparty:t.recipientId}
    : {id:t.reference+'-R',title:'Transfer from '+t.senderName,subtitle:'Received from '+t.senderName+' • Demo',amount:t.amount,incoming:true,createdAt:t.createdAt,counterparty:t.senderId}
  );
}
export const handler = router({
  'POST /api/register': [async ({body}) => {
    const b=body as {name?:string;email?:string;phone?:string;password?:string;pin?:string};
    const name=b.name?.trim()||'', email=normalizeEmail(b.email||''), phone=normalizePhone(b.phone||''), password=b.password||'', pin=b.pin||'';
    if(name.length<2) return error('Enter your full name.',400);
    if(!/^\S+@\S+\.\S+$/.test(email)) return error('Enter a valid email address.',400);
    const localPhone=phone.replace(/^\+?234/,'0');
    if(!/^0[789][01]\d{8}$/.test(localPhone)) return error('Enter a valid Nigerian phone number, for example 08012345678.',400);
    if(password.length<8) return error('Password must be at least 8 characters.',400);
    if(!/^\d{4}$/.test(pin)) return error('Transaction PIN must be 4 digits.',400);
    const {items}=await db.list<User>('users',{limit:100});
    if(items.some(u=>normalizeEmail(u.email)===email)) return error('An account with this email already exists.',409);
    if(items.some(u=>normalizePhone(u.phone)===phone)) return error('An account with this phone number already exists.',409);
    const code=String(crypto.randomInt(100000,1000000));
    const [id]=await db.add('users',[{name,email,phone,passwordHash:hash(password),verified:false,verificationHash:hash(code),verificationExpires:Date.now()+600000,pinHash:hash(pin),balance:250000,createdAt:Date.now()}]);
    if(!id) return error('Could not create account.',500);
    try { await sendVerification(email,code); return json({ok:true,userId:id,message:'Verification code sent to your email.'}); } catch { const [created]=await db.get<User>('users',[id]); if(!created) return error('Account could not be created.',500); const verified={...created,verified:true,verificationHash:undefined,verificationExpires:undefined}; await db.update('users',[{id,record:verified as Record<string,unknown>}]); return json({ok:true,userId:id,user:publicUser(verified,id),message:'Account created. Email delivery is unavailable, so this demo account was verified automatically.'}); }
  }],
  'POST /api/verify': [async ({body}) => {
    const b=body as {userId?:string;code?:string}; const id=b.userId||'', code=b.code||'';
    if(!id || !/^\d{6}$/.test(code)) return error('Enter the 6-digit verification code.',400);
    const [u]=await db.get<User>('users',[id]); if(!u) return error('Account not found.',404);
    if(u.verified) return json({ok:true,user:publicUser(u,id)});
    if(!u.verificationExpires || Date.now()>u.verificationExpires) return error('That verification code has expired. Please register again.',400);
    if(hash(code)!==u.verificationHash) return error('Incorrect verification code.',400);
    const updated={...u,verified:true,verificationHash:undefined,verificationExpires:undefined};
    const [ok]=await db.update('users',[{id,record:updated as Record<string,unknown>}]); if(!ok) return error('Could not verify account.',500);
    return json({ok:true,user:publicUser(updated,id)});
  }],
  'POST /api/login': [async ({body}) => {
    const b=body as {identifier?:string;password?:string}; const u=await findUser(b.identifier||'');
    if(!u || u.passwordHash!==hash(b.password||'')) return error('Incorrect email/phone or password.',401);
    if(!u.verified) return error('Please verify your email before logging in.',403);
    return json({ok:true,user:publicUser(u,u.id)});
  }],
  'POST /api/recover/request': [async ({body}) => {
    const b=body as {identifier?:string};
    const u=await findUser(b.identifier||'');
    if(!u || !u.verified) return error('No verified Bay U account was found with that email or phone number.',404);
    const code=String(crypto.randomInt(100000,1000000));
    const updated={...u,verificationHash:hash(code),verificationExpires:Date.now()+600000};
    const [ok]=await db.update('users',[{id:u.id,record:updated as Record<string,unknown>}]);
    if(!ok) return error('Recovery could not be started. Please try again.',500);
    try { await sendVerification(u.email,code); } catch { return error('We could not send the recovery code to the account email. Please try again.',502); }
    return json({ok:true,userId:u.id,message:'A recovery code was sent to the email on your Bay U account.'});
  }],
  'POST /api/recover/complete': [async ({body}) => {
    const b=body as {userId?:string;code?:string;newPassword?:string};
    const id=b.userId||'', code=b.code||'', newPassword=b.newPassword||'';
    if(!id || !/^\d{6}$/.test(code)) return error('Enter the 6-digit recovery code.',400);
    if(newPassword.length<8) return error('New password must be at least 8 characters.',400);
    const [u]=await db.get<User>([id] as any);
    if(!u) return error('Account not found.',404);
    if(!u.verificationExpires || Date.now()>u.verificationExpires) return error('That recovery code has expired. Request a new one.',400);
    if(hash(code)!==u.verificationHash) return error('Incorrect recovery code.',400);
    const updated={...u,passwordHash:hash(newPassword),verificationHash:undefined,verificationExpires:undefined};
    const [ok]=await db.update('users',[{id,record:updated as Record<string,unknown>}]);
    if(!ok) return error('Password could not be reset safely. Please try again.',500);
    return json({ok:true,user:publicUser(updated,id),message:'Password reset successfully.'});
  }],
  'PUT /api/profile/:id': [async ({params,body}) => {
    const b=body as {name?:string;phone?:string};
    const [u]=await db.get<User>([params.id]);
    if(!u) return error('Account not found.',404);
    const name=(b.name||'').trim(), phone=normalizePhone(b.phone||'');
    if(name.length<2) return error('Enter a valid full name.',400);
    const localPhone=phone.replace(/^\+?234/,'0');
    if(!/^0[789][01]\d{8}$/.test(localPhone)) return error('Enter a valid Nigerian phone number.',400);
    const {items}=await db.list<User>('users',{limit:100});
    if(items.some(x=>normalizePhone(x.phone)===phone && normalizePhone(x.phone)!==normalizePhone(u.phone))) return error('That phone number is already in use.',409);
    const updated={...u,name,phone};
    const [ok]=await db.update('users',[{id:params.id,record:updated as Record<string,unknown>}]);
    if(!ok) return error('Personal details could not be updated.',500);
    return json({ok:true,user:publicUser(updated,params.id)});
  }],
  'POST /api/security/password': [async ({body}) => {
    const b=body as {userId?:string;currentPassword?:string;newPassword?:string};
    const [u]=await db.get<User>([b.userId||'']);
    if(!u) return error('Account not found.',404);
    if(u.passwordHash!==hash(b.currentPassword||'')) return error('Current password is incorrect.',401);
    if((b.newPassword||'').length<8) return error('New password must be at least 8 characters.',400);
    const updated={...u,passwordHash:hash(b.newPassword||'')};
    const [ok]=await db.update('users',[{id:b.userId||'',record:updated as Record<string,unknown>}]);
    if(!ok) return error('Password could not be changed.',500);
    return json({ok:true,message:'Password changed successfully.'});
  }],
  'POST /api/security/pin': [async ({body}) => {
    const b=body as {userId?:string;currentPin?:string;newPin?:string};
    const [u]=await db.get<User>([b.userId||'']);
    if(!u) return error('Account not found.',404);
    if(u.pinHash!==hash(b.currentPin||'')) return error('Current transaction PIN is incorrect.',401);
    if(!/^\d{4}$/.test(b.newPin||'')) return error('New transaction PIN must be 4 digits.',400);
    const updated={...u,pinHash:hash(b.newPin||'')};
    const [ok]=await db.update('users',[{id:b.userId||'',record:updated as Record<string,unknown>}]);
    if(!ok) return error('Transaction PIN could not be changed.',500);
    return json({ok:true,message:'Transaction PIN changed successfully.'});
  }],
  'GET /api/account/:id': [async ({params}) => {
    const [u]=await db.get<User>('users',[params.id]); if(!u) return error('Account not found.',404);
    const baseHistory=await txs(params.id); const transfers=await demoTransfers(params.id);
    return json({user:{...publicUser(u,params.id),balance:demoBalance(u.balance,params.id,transfers)},transactions:baseHistory});
  }],
  'POST /api/transactions': [async ({body}) => {
    const b=body as {userId?:string;title?:string;subtitle?:string;amount?:number;incoming?:boolean;createdAt?:number};
    const userId=b.userId||''; const [u]=await db.get<User>('users',[userId]);
    if(!u) return error('Account not found.',404);
    if(!b.title) return error('Transaction title is required.',400);
    const [id]=await db.add('transactions',[{userId,title:b.title,subtitle:b.subtitle||'Bay U simulation • Just now',amount:Number(b.amount)||0,incoming:!!b.incoming,createdAt:Number(b.createdAt)||Date.now()}]);
    if(!id) return error('Transaction history could not be saved.',500);
    return json({ok:true,id});
  }],
  'GET /api/recipient': [async ({query}) => {
    const identifier=query.identifier||''; const u=await findUser(identifier);
    if(!u || !u.verified) return error('Bay U recipient not found.',404);
    return json({id:u.id,name:u.name,phone:u.phone,email:u.email});
  }],
  'POST /api/transfer': [async ({body}) => {
    const b=body as {senderId?:string;recipientIdentifier?:string;amount?:number;pin?:string};
    const amount=Number(b.amount)||0; const senderId=b.senderId||'';
    if(amount<=0) return error('Enter a valid amount.',400);
    const [sender]=await db.get<User>('users',[senderId]); if(!sender) return error('Sender account not found.',404);
    if(sender.pinHash!==hash(b.pin||'')) return error('Incorrect transaction PIN.',401);
    const recipient=await findUser(b.recipientIdentifier||'');
    if(!recipient || !recipient.verified || !recipient.id) return error('Bay U recipient not found.',404);
    if(recipient.id===senderId) return error('You cannot transfer to yourself.',400);
    const existing=await demoTransfers(senderId); const senderBalance=demoBalance(sender.balance,senderId,existing);
    if(senderBalance<amount) return error('Insufficient demo balance.',400);
    const reference='BU-DEMO-'+Date.now().toString(36).toUpperCase();
    const transfer:DemoTransfer={reference,senderId,recipientId:recipient.id,amount,createdAt:Date.now(),senderName:sender.name,recipientName:recipient.name};
    const [id]=await db.add('transactions',[
      {userId:senderId,title:'Transfer to '+recipient.name,subtitle:'Sent to '+recipient.name+' • Demo',amount,incoming:false,createdAt:transfer.createdAt,counterparty:recipient.id,demoReference:reference,demoSenderId:senderId,demoRecipientId:recipient.id,demoSenderName:sender.name,demoRecipientName:recipient.name},
      {userId:recipient.id,title:'Transfer from '+sender.name,subtitle:'Received from '+sender.name+' • Demo',amount,incoming:true,createdAt:transfer.createdAt,counterparty:senderId,demoReference:reference,demoSenderId:senderId,demoRecipientId:recipient.id,demoSenderName:sender.name,demoRecipientName:recipient.name}
    ]);
    if(!id) return error('Demo transfer could not be recorded. Please try again.',500);
    const all=await demoTransfers(senderId); const newBalance=demoBalance(sender.balance,senderId,all);
    return json({ok:true,amount,reference,recipient:{id:recipient.id,name:recipient.name,phone:recipient.phone,email:recipient.email},sender:{id:senderId,name:sender.name,phone:sender.phone,email:sender.email},senderBalance:newBalance,message:'Bay U demo transfer recorded. No real money moved.'});
  }]
});