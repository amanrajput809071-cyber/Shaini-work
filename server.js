import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import path from "path";
import {fileURLToPath} from "url";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express(), PORT=process.env.PORT||3000;
const JWT_SECRET=process.env.JWT_SECRET||"CHANGE_THIS_SECRET";
const db=new Database(process.env.DB_FILE||path.join(__dirname,"shaini.db"));
db.pragma("journal_mode=WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 phone TEXT UNIQUE NOT NULL,
 role TEXT NOT NULL DEFAULT 'member',
 status TEXT NOT NULL DEFAULT 'active',
 earning INTEGER NOT NULL DEFAULT 0,
 portals INTEGER NOT NULL DEFAULT 0,
 customers INTEGER NOT NULL DEFAULT 0,
 paid INTEGER NOT NULL DEFAULT 0,
 pending INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS portals(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,url TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS activities(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,activity TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Completed',amount INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
`);

if(!db.prepare("SELECT id FROM users WHERE username='admin'").get()){
 const h=bcrypt.hashSync(process.env.ADMIN_PASSWORD||"ChangeMe123!",12);
 db.prepare("INSERT INTO users(name,username,password_hash,phone,role) VALUES(?,?,?,?,?)")
 .run("SHAINI Admin","admin",h,"0000000000","admin");
}
if(db.prepare("SELECT COUNT(*) c FROM portals").get().c===0){
 const ins=db.prepare("INSERT INTO portals(name,url) VALUES(?,?)");
 for(let i=1;i<=5;i++) ins.run("Portal "+i,"https://example.com/portal"+i);
}
app.use(express.json());
app.use(express.static(path.join(__dirname,"public")));

function auth(req,res,next){
 const h=req.headers.authorization||"";
 if(!h.startsWith("Bearer "))return res.status(401).json({error:"Login required"});
 try{req.user=jwt.verify(h.slice(7),JWT_SECRET);next()}catch{return res.status(401).json({error:"Session expired"})}
}
function admin(req,res,next){if(req.user.role!=="admin")return res.status(403).json({error:"Admin only"});next()}
function token(u){return jwt.sign({id:u.id,role:u.role},JWT_SECRET,{expiresIn:"12h"})}

app.post("/api/register",(req,res)=>{
 const {name,phone,username,password}=req.body||{};
 if(!name||!phone||!username||!password)return res.status(400).json({error:"Name, mobile number, username and password are required"});
 if(!/^[6-9]\d{9}$/.test(String(phone)))return res.status(400).json({error:"Enter a valid 10-digit Indian mobile number"});
 if(String(password).length<6)return res.status(400).json({error:"Password must be at least 6 characters"});
 if(username==="admin")return res.status(400).json({error:"This username is reserved"});
 try{
  const h=bcrypt.hashSync(password,12);
  const r=db.prepare("INSERT INTO users(name,username,password_hash,phone) VALUES(?,?,?,?)").run(String(name).trim(),String(username).trim(),h,String(phone));
  res.json({ok:true,id:r.lastInsertRowid,message:"Account created successfully"});
 }catch(e){res.status(400).json({error:"Mobile number or username already registered"})}
});

app.post("/api/login",(req,res)=>{
 const {username,password}=req.body||{};
 const u=db.prepare("SELECT * FROM users WHERE username=? AND status='active'").get(username||"");
 if(!u||!bcrypt.compareSync(password||"",u.password_hash))return res.status(401).json({error:"Username or password is incorrect"});
 res.json({token:token(u),user:{id:u.id,name:u.name,username:u.username,role:u.role}});
});

app.get("/api/me",auth,(req,res)=>{
 const u=db.prepare("SELECT id,name,username,phone,role,status,earning,portals,customers,paid,pending FROM users WHERE id=?").get(req.user.id);
 const portals=db.prepare("SELECT id,name,url FROM portals ORDER BY id").all();
 const activities=db.prepare("SELECT activity,status,amount,created_at FROM activities WHERE user_id=? ORDER BY id DESC LIMIT 50").all(req.user.id);
 res.json({user:u,portals,activities});
});

app.get("/api/admin/users",auth,admin,(req,res)=>{
 res.json(db.prepare("SELECT id,name,username,phone,status,earning,portals,customers,paid,pending,created_at FROM users WHERE role='member' ORDER BY id DESC").all());
});
app.post("/api/admin/users",auth,admin,(req,res)=>{
 const {name,phone,username,password}=req.body||{};
 if(!name||!phone||!username||!password)return res.status(400).json({error:"All fields required"});
 try{
  const h=bcrypt.hashSync(password,12);
  const r=db.prepare("INSERT INTO users(name,username,password_hash,phone) VALUES(?,?,?,?)").run(name,username,h,phone);
  res.json({ok:true,id:r.lastInsertRowid});
 }catch{res.status(400).json({error:"Username or mobile already exists"})}
});
app.patch("/api/admin/users/:id",auth,admin,(req,res)=>{
 const id=Number(req.params.id), b=req.body||{}, allowed=["name","phone","status","earning","portals","customers","paid","pending"];
 const f=[],v=[];
 for(const k of allowed)if(b[k]!==undefined){f.push(k+"=?");v.push(["name","phone","status"].includes(k)?String(b[k]):Math.max(0,Number(b[k])||0))}
 if(!f.length)return res.status(400).json({error:"No changes"});
 v.push(id);db.prepare("UPDATE users SET "+f.join(",")+" WHERE id=? AND role='member'").run(...v);res.json({ok:true});
});
app.post("/api/admin/activity",auth,admin,(req,res)=>{
 const {user_id,activity,status="Completed",amount=0}=req.body||{};
 if(!user_id||!activity)return res.status(400).json({error:"User and activity required"});
 db.prepare("INSERT INTO activities(user_id,activity,status,amount) VALUES(?,?,?,?)").run(Number(user_id),activity,status,Math.max(0,Number(amount)||0));
 res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log("SHAINI WORK: http://localhost:"+PORT));