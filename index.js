const {tokenValidation, roleCheck} = require('./auth')
const express = require("express");
const mongodb = require("mongodb");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

const mongoClient = mongodb.MongoClient;
const objectId = mongodb.ObjectID;
const port = process.env.PORT || 3000;
const dbUrl = process.env.DB_URL || "mongodb://127.0.0.1:27017";
const saltRounds = 10;

// Nodemailer email authentication
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});

// Details of data to be sent in verification email
const mailData = {
  from: process.env.EMAIL,
  subject: "Reset your password",
};

// Details of data to be sent in verification email
const mailDataActivate = {
  from: process.env.EMAIL,
  subject: "Activate your account",
};

// Message to be sent in the verification email
let mailMessage = (url) => {
  return `<p>Hi there,<br> You have been requested to reset your password.<br>please click on the link below to reset the password.<br><a href='${url}' target='_blank'>${url}</a><br>Thank you...</p>`;
};

// Message to be sent in the verification email while registration
let mailMessageActivate = (url) => {
  return `<p>Hi there,<br> You have been registered in our website.<br>please click on the link below to activate your account.<br><a href='${url}' target='_blank'>${url}</a><br />If not registered by you do not click this link.<br>Thank you...</p>`;
};

// This end-point helps to create new user
app.post("/register-user", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("forum_app_db");
    let user = await db.collection("users").findOne({ email: req.body.email });
    let random_string = Math.random().toString(36).substring(5).toUpperCase();
    if (!user) {
      let salt = await bcrypt.genSalt(saltRounds);
      let hash = await bcrypt.hash(req.body.password, salt);
      let as = await bcrypt.hash(random_string, salt);
      req.body.password = hash;
      req.body.activate_string = as;
      req.body.isActive = false;
      req.body.role = "user"
      await db.collection("users").insertOne(req.body);
      let regUser = await db.collection("users").findOne({ email: req.body.email });
      let usrActivateUrl = `${process.env.PWDREGURL}?id=${regUser._id}&usa=${req.body.activate_string}`;
      mailDataActivate.to = req.body.email;
      mailDataActivate.html = mailMessageActivate(usrActivateUrl);
      await transporter.sendMail(mailDataActivate);
      res.status(200).json({ message: "activation link sent to mail" });
    } else {
      res.status(400).json({ message: "user already exists, please login" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

// This end-point helps to login the existing user
app.post("/login", async (req, res) => {
  try {
    console.log(req.body.isValidated)
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("forum_app_db");
    let user = await db.collection("users").findOne({ email: req.body.email });
    if (user) {
      if (user.isActive){
        let token = await jwt.sign({
          user_id: user._id, 
          role: user.role
        }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' })
        let compare = await bcrypt.compare(req.body.password, user.password);
        if (compare) {
          res.status(200).json({ message: "user logged in successfully", token });
        } else {
          res.status(401).json({ message: "incorrect password" });
        }
      }else{
        res.status(403).json({message: "user is not activated. check your mail for more information"});
      }
    } else {
      res.status(400).json({ message: "user not found" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

// This end-point helps the user to generate verification mail to reset the password
app.post("/forgot-password", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("forum_app_db");
    let random_string = Math.random().toString(36).substring(5).toUpperCase();
    let user = await db.collection("users").findOne({ email: req.body.email });
    if (user) {
      let salt = await bcrypt.genSalt(saltRounds);
      let hash = await bcrypt.hash(random_string, salt);
      req.body.random_string = hash;
      await db
        .collection("users")
        .findOneAndUpdate(
          { email: req.body.email },
          { $set: { random_string: req.body.random_string } }
        );
      let pwResetUrl = `${process.env.PWRESETURL}?id=${user._id}&rps=${req.body.random_string}`;
      mailData.to = req.body.email;
      mailData.html = mailMessage(pwResetUrl);
      await transporter.sendMail(mailData);
      res.status(200).json({ message: "Password reset link sent to email" });
    } else {
      res.status(403).json({ message: "user is not registered" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

// This end-point helps to verify the randomly generated string used for changing the password
app.post("/verify-random-string", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("forum_app_db");
    let user = await db.collection("users").findOne({ _id: objectId(req.body._id) });
    let unicodeString = req.body.verificationString
    req.body.verificationString = decodeURIComponent(JSON.parse('"' + unicodeString.replace(/\"/g, '\\"') + '"'));
    if (user) {
      if (user.random_string == req.body.verificationString) {
        res.status(200).json({ message: "verification string valid" });
      } else {
        res.status(403).json({ message: "verification string not valid" });
      }
    } else {
      res.status(403).json({ message: "user doesn't exist" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.post("/activate-user", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("forum_app_db");
    let user = await db.collection("users").findOne({ _id: objectId(req.body._id) });
    let unicodeString = req.body.activationString
    req.body.activationString = decodeURIComponent(JSON.parse('"' + unicodeString.replace(/\"/g, '\\"') + '"'));
    if (user) {
      if (user.activate_string == req.body.activationString) {
        await db.collection('users').findOneAndUpdate({_id: user._id}, {$set: {activate_string: "something which is not good", isActive: true}})
        res.status(200).json({ message: "activation successfull" });
      } else {
        res.status(403).json({ message: "activation string is not valid" });
      }
    } else {
      res.status(403).json({ message: "user doesn't exist" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

// This end-point helps to set a new password only if the conditions are met
app.put("/assign-password", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("forum_app_db");
    let user = await db
      .collection("users")
      .findOne({ _id: objectId(req.body._id) });
      console.log(user)
    let unicodeString = req.body.verificationString
    req.body.verificationString = decodeURIComponent(JSON.parse('"' + unicodeString.replace(/\"/g, '\\"') + '"'));
    if (user.random_string == req.body.verificationString) {
      let salt = await bcrypt.genSalt(saltRounds);
      let hash = await bcrypt.hash(req.body.password, salt);
      req.body.password = hash;
      await db
        .collection("users")
        .findOneAndUpdate(
          { _id: objectId(req.body._id) },
          { $set: { random_string: "JustARandomStringWithoutHashing" } }
        );
      await db
        .collection("users")
        .findOneAndUpdate(
          { _id: objectId(req.body._id) },
          { $set: { password: req.body.password } }
        );
      res.status(200).json({ message: "password changed successfully" });
    } else {
      res.status(403).json({ message: "user with the id not found" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.post('/add-topic', tokenValidation, async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl)
    let db = client.db('forum_app_db');
    let data = {
      created_on: new Date(),
      created_by: req.body.id,
      topic_title: req.body.topic_title,
      content: req.body.content
    }
    let topics = await db.collection('topics').insertOne(data);
    res.status(200).json({message: "topic added successfully"});
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
})

app.post("/edit-topic", tokenValidation, async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    await db.collection('topics').findOneAndUpdate({_id: objectId(req.body.topic_id)}, {$set: {topic_title: req.body.topic_title, content: req.body.content}});
    let topic = await db.collection('topics').findOne({_id: objectId(req.body.topic_id)});
    res.status(200).json({message: 'topic edited successfully'});
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500)
  }
})

app.get("/topics", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    let topics = await db.collection('topics').find().toArray();
    res.status(200).json({message: "topics fetched successfully", topics})
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500); 
  }
})

app.post("/user-topics", tokenValidation, async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    let user = await db.collection('users').findOne({_id: objectId(req.body.id)}, {fields: { fname: 1, lname: 1, email: 1, role: 1}})
    let topics = await db.collection('topics').find().toArray();
    let data = {user: user, topics: topics}
    res.status(200).json({message: "topics fetched successfully", data})
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500); 
  }
})

app.post('/add-comment', tokenValidation, async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    let data = {
      topic_id: req.body.topic_id,
      comment: req.body.comment,
      commented_by: req.body.id,
      commented_on: new Date()
    }
    await db.collection('comments').insertOne(data);
    res.status(200).json({message: 'comment is added successfully'})
    client.close();
  } catch (error) {
    console.log(error);
    req.sendStatus(500)
  }
})

app.put('/edit-comment', tokenValidation, async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    await db.collection('comments').findOneAndUpdate({_id: objectId(req.body.comment_id)}, {$set: {comment: req.body.comment}});
    res.status(200).json({message: 'comment is edited successfully'});
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
})

app.get('/comments/:id', async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    let comments = await db.collection('comments').find({topic_id: req.params.id}).toArray();
    res.status(200).json({message: "comments for requested topic fetched successfully", comments});
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
})

app.post('/delete-topic', tokenValidation, roleCheck("admin"), async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    let topic = await db.collection('topics').findOneAndDelete({_id: objectId(req.body.topic_id)});
    res.status(200).json({message: 'topic has been deleted successfully'});
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
})

app.post('/delete-comment', tokenValidation, roleCheck("admin"), async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    let comment = await db.collection('comments').findOneAndDelete({_id: objectId(req.body.comment_id)});
    res.status(200).json({message: 'comment has been deleted successfully'});
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
})

app.post('/search', async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    await db.collection('topics').createIndex( { topic_title: "text", content: "text" } );
    let result = await db.collection('topics').find({ $text: { $search: req.body.text}  , created_on: {$gte: new Date(req.body.from_date), $lte: new Date(req.body.to_date)} }).limit(req.body.limit).toArray();
    res.status(200).json({message: 'fetched search results', result});
    client.close()
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
})

app.get('/user-details/:id', async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    let data = await db.collection('users').findOne({_id: objectId(req.params.id)}, {fields: {fname: 1, lname: 1, email: 1, role: 1}});
    res.status(200).json({message: 'user details fetched successfully', data});
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
})

app.post('/tokenValid', tokenValidation, async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('forum_app_db');
    let data = await db.collection('users').findOne({_id: objectId(req.body.id)});
    if(data){
      res.status(200).json({message: 'token is validated succcessfully'})
    }else{
      res.status(403).json({message: 'token validation is unsuccessful'})
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
})

app.listen(port, () => console.log(port));