const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.SECRET_KEY);
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const path = require('path');

// Initialize Socket.IO
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: true, // Matches your existing CORS origin
    methods: ['GET', 'POST'],
    credentials: true,
  },
});


// Multer for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'Uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only images are allowed'), false);
    }
  },
});

app.use('/uploads', express.static(path.join(__dirname, 'Uploads')));

const app = express();
const port = process.env.PORT || 3000;

// MongoDB URI
const user = process.env.USER_DB;
const pass = process.env.USER_PASS;
const uri = `mongodb+srv://${user}:${pass}@mdb.26vlivz.mongodb.net/?retryWrites=true&w=majority&appName=MDB`;

// Middleware
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

// JWT Generator
function generateToken(user) {
  return jwt.sign(
    { email: user.email, uid: user.uid, role: user.role },
    process.env.JWT_SECRET
  );
}

// JWT Verifier
function verifyJWT(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).send({ message: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: "Forbidden" });
    req.user = decoded;
    next();
  });
}

// MongoDB + App Boot
async function run() {
  try {
    const client = new MongoClient(uri, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    });

    const db = client.db("codecircleDB");
    const userCollection = db.collection("users");
    const postTagCollection = db.collection("postTags");
    const postsCollection = db.collection("posts");
    const membershipplans = db.collection("membershipplans");
    const paymentHistory = db.collection("paymentHistory");
    const messagesCollection = db.collection('messages');

    // Routes
    app.post("/jwt", async (req, res) => {
      const { email } = req.body;
      if (!email) return res.status(400).send({ message: "Email is required" });

      const user = await userCollection.findOne({ email });
      if (!user) return res.status(404).send({ message: "User not found" });

      const token = generateToken(user);

      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        })
        .send({ success: true, message: "JWT set in cookie" });
    });

    app.post("/logout", (req, res) => {
      res
        .clearCookie("token", {
          httpOnly: true,
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production",
        })
        .send({ success: true, message: "Logged out" });
    });

    app.get("/search", async (req, res) => {
      const query = req.query.q?.toLowerCase();
      if (!query)
        return res.status(400).send({ message: "Missing search query" });

      try {
        const results = await db
          .collection("posts")
          .find({
            $or: [
              { postTitle: { $regex: query, $options: "i" } },
              { postDescription: { $regex: query, $options: "i" } },
              { tag: { $regex: query, $options: "i" } }, 
            ],
          })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(results);
      } catch (err) {
        console.error("❌ Search error:", err);
        res.status(500).send({ message: "Failed to search posts" });
      }
    });

    app.get("/search-suggestions", async (req, res) => {
      const query = req.query.q?.toLowerCase();
      if (!query) return res.status(400).send([]);

      try {
        const results = await db
          .collection("posts")
          .find({
            $or: [
              { postTitle: { $regex: query, $options: "i" } },
              { tags: { $elemMatch: { $regex: query, $options: "i" } } },
            ],
          })
          .limit(5)
          .project({ postTitle: 1 })
          .toArray();

        res.send(results);
      } catch (err) {
        console.error("Suggestion error:", err);
        res.status(500).send([]);
      }
    });

    //  Get All Tags
    app.get("/tags", async (req, res) => {
      try {
        const tags = await postTagCollection.find().toArray();
        res.send(tags);
      } catch (err) {
        console.error("❌ Error fetching tags:", err);
        res.status(500).send({ message: "Failed to fetch tags" });
      }
    });

    //  Add Tag
    app.post("/tags", async (req, res) => {
      try {
        const { tag } = req.body;
        if (!tag || typeof tag !== "string") {
          return res
            .status(400)
            .send({ message: "Tag must be a non-empty string" });
        }

        const tagDoc = {
          tag: tag.toLowerCase().trim(),
          createdAt: new Date(),
        };

        const result = await postTagCollection.insertOne(tagDoc);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        console.error("❌ Tag insert error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    //  Get All Users
    app.get("/users", async (req, res) => {
      try {
        const users = await userCollection.find().toArray();

        // Force special email always admin
        users.forEach((user) => {
          if (user.email === "admin@code-circle.com") {
            user.role = "admin";
          }
        });

        res.send(users);
      } catch (err) {
        console.error("❌ Error fetching users:", err);
        res.status(500).send({ message: "Failed to fetch users" });
      }
    });

    //  Create New User
    app.post("/users", async (req, res) => {
      try {
        const { uid, email, fullName, photoURL, badge } = req.body;

        if (!email) {
          return res.status(400).send({ message: "Email is required" });
        }

        const existingUser = await userCollection.findOne({ email });

        if (existingUser) {
          return res.status(409).send({ message: "User already exists" });
        }

        const userDoc = {
          uid,
          email,
          fullName: fullName || null,
          photoURL: photoURL || null,
          badge: badge || "Bronze",
          createdAt: new Date(),
          role: "user",
        };

        const result = await userCollection.insertOne(userDoc);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        console.error("❌ Error adding user:", err);
        res.status(500).send({ message: "Failed to add user" });
      }
    });

    // POST /jwt
    app.post("/jwt", async (req, res) => {
      const { email } = req.body;

      if (!email) return res.status(400).send({ message: "Email is required" });

      const user = await userCollection.findOne({ email });
      if (!user) return res.status(404).send({ message: "User not found" });

      const token = generateToken(user);

      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        })
        .send({ success: true, message: "JWT set in cookie" });
    });

    //  Update User
    app.put("/users/:id", async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ error: "Invalid user id" });
      }

      const { _id, ...updateData } = req.body;

      try {
        const result = await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ error: "User not found" });
        }

        res.send(result);
      } catch (err) {
        console.error("Update failed:", err);
        res.status(500).send({ error: "Failed to update profile" });
      }
    });

    //  Get Posts (All or 3 recent by user email)
    app.get("/posts", async (req, res) => {
      const { authorEmail, popular } = req.query;

      try {
        if (popular === "true") {
          const popularPosts = await postsCollection
            .aggregate([
              {
                $addFields: {
                  voteDifference: { $subtract: ["$upVote", "$downVote"] },
                },
              },
              {
                $sort: { voteDifference: -1 },
              },
            ])
            .toArray();

          return res.send(popularPosts);
        }

        if (authorEmail) {
          const posts = await postsCollection
            .find({ authorEmail })
            .sort({ createdAt: -1 })
            .toArray();

          return res.send(posts);
        }

        const posts = await postsCollection
          .find()
          .sort({ createdAt: -1 })
          .toArray();

        res.send(posts);
      } catch (err) {
        console.error("❌ Error fetching posts:", err);
        res.status(500).send({ message: "Failed to fetch posts" });
      }
    });

    // Get single post by id
    app.get("/posts/:id", async (req, res) => {
      const postId = req.params.id;
      if (!ObjectId.isValid(postId))
        return res.status(400).send({ message: "Invalid post ID" });

      try {
        const post = await postsCollection.findOne({
          _id: new ObjectId(postId),
        });
        if (!post) return res.status(404).send({ message: "Post not found" });
        res.send(post);
      } catch (err) {
        console.error("Error fetching post:", err);
        res.status(500).send({ message: "Failed to fetch post" });
      }
    });

    //  Add New Post
    app.post("/posts", async (req, res) => {
      const postData = req.body;

      if (
        !postData?.authorEmail ||
        !postData?.postTitle ||
        !postData?.postDescription
      ) {
        return res
          .status(400)
          .send({ message: "Missing required post fields" });
      }

      const newPost = {
        ...postData,
        upVote: 0,
        downVote: 0,
        createdAt: new Date(),
      };

      try {
        const result = await postsCollection.insertOne(newPost);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        console.error("❌ Failed to add post:", err);
        res.status(500).send({ message: "Failed to add post" });
      }
    });

    app.put("/posts/vote/:id", async (req, res) => {
      const postId = req.params.id;
      const { voteType, userEmail } = req.body;

      if (!ObjectId.isValid(postId))
        return res.status(400).send({ message: "Invalid post ID" });
      if (!["upvote", "downvote"].includes(voteType))
        return res.status(400).send({ message: "Invalid vote type" });
      if (!userEmail)
        return res.status(400).send({ message: "Missing userEmail" });

      try {
        const post = await postsCollection.findOne({
          _id: new ObjectId(postId),
        });
        if (!post) return res.status(404).send({ message: "Post not found" });

        const voters = post.voters || [];
        const existingVote = voters.find((v) => v.email === userEmail);

        let update = {};
        let newVoters;

        if (!existingVote) {
          // New vote
          update =
            voteType === "upvote"
              ? { $inc: { upVote: 1 } }
              : { $inc: { downVote: 1 } };

          newVoters = [...voters, { email: userEmail, type: voteType }];
        } else if (existingVote.type === voteType) {
          // Remove vote
          update =
            voteType === "upvote"
              ? { $inc: { upVote: -1 } }
              : { $inc: { downVote: -1 } };

          newVoters = voters.filter((v) => v.email !== userEmail);
        } else {
          // Switch vote
          update =
            voteType === "upvote"
              ? { $inc: { upVote: 1, downVote: -1 } }
              : { $inc: { upVote: -1, downVote: 1 } };

          newVoters = voters.map((v) =>
            v.email === userEmail ? { email: userEmail, type: voteType } : v
          );
        }

        await postsCollection.updateOne(
          { _id: new ObjectId(postId) },
          {
            ...update,
            $set: { voters: newVoters },
          }
        );

        res.send({ success: true, message: "Vote updated" });
      } catch (err) {
        console.error("Vote error:", err);
        res.status(500).send({ message: "Failed to update vote" });
      }
    });

    //  DELETE Post
    app.delete("/posts/:id", async (req, res) => {
      const postId = req.params.id;
      const email = req.query.email;

      if (!ObjectId.isValid(postId)) {
        return res.status(400).send({ message: "Invalid post ID" });
      }

      try {
        const post = await postsCollection.findOne({
          _id: new ObjectId(postId),
        });
        if (!post) return res.status(404).send({ message: "Post not found" });

        if (post.authorEmail !== email) {
          return res
            .status(403)
            .send({ message: "You are not authorized to delete this post" });
        }

        await postsCollection.deleteOne({ _id: new ObjectId(postId) });
        res.send({ success: true, message: "Post deleted by author" });
      } catch (err) {
        console.error("Author post delete error:", err);
        res.status(500).send({ message: "Failed to delete post" });
      }
    });

    // GET /comments — Get all comments (no filter)
    app.get("/comments", async (req, res) => {
      try {
        const comments = await db.collection("comments").find().toArray();
        res.send(comments);
      } catch (err) {
        console.error("❌ Failed to fetch all comments:", err);
        res.status(500).send({ message: "Failed to fetch comments" });
      }
    });

    //  Get comment count
    app.get("/comments/count", async (req, res) => {
      const title = req.query.title;
      if (!title)
        return res.status(400).send({ message: "Missing post title" });

      try {
        const count = await db
          .collection("comments")
          .countDocuments({ postTitle: title });
        res.send({ count });
      } catch (err) {
        console.error("❌ Failed to count comments:", err);
        res.status(500).send({ message: "Failed to get comment count" });
      }
    });

    // Get comments by postId
    app.get("/comments/:postId", async (req, res) => {
      const { postId } = req.params;
      if (!ObjectId.isValid(postId))
        return res.status(400).send({ message: "Invalid post ID" });

      try {
        const comments = await db
          .collection("comments")
          .find({ postId: new ObjectId(postId) })
          .toArray();
        res.send(comments);
      } catch (err) {
        console.error("Failed to fetch comments:", err);
        res.status(500).send({ message: "Failed to fetch comments" });
      }
    });

    //  Add comment
    app.post("/comments", async (req, res) => {
      const { postId, commentText, commenterEmail } = req.body;
      if (!postId || !commentText || !commenterEmail) {
        return res
          .status(400)
          .send({ message: "Missing required comment fields" });
      }

      try {
        const newComment = {
          postId: new ObjectId(postId),
          commentText,
          commenterEmail,
          createdAt: new Date(),
        };
        const result = await db.collection("comments").insertOne(newComment);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        console.error("Failed to add comment:", err);
        res.status(500).send({ message: "Failed to add comment" });
      }
    });

    // GET all comment reports
    app.get("/comment-reports", async (req, res) => {
      try {
        const reports = await db
          .collection("commentReports")
          .find()
          .sort({ reportedAt: -1 })
          .toArray();
        res.send(reports);
      } catch (err) {
        console.error("❌ Failed to fetch comment reports:", err);
        res.status(500).send({ message: "Failed to fetch comment reports" });
      }
    });

    app.post("/comment-reports", async (req, res) => {
      const {
        commentId,
        commentText,
        commenterEmail,
        postId,
        feedback,
        reportedBy,
      } = req.body;
      await db.collection("commentReports").insertOne({
        commentId: new ObjectId(commentId),
        commentText,
        commenterEmail,
        postId,
        feedback,
        reportedBy,
        reportedAt: new Date(),
      });
      res.send({ success: true });
    });

    // POST /announcements — Create new announcement
    app.post("/announcements", async (req, res) => {
      const { title, description, authorName, authorImage } = req.body;

      if (!title || !description || !authorName) {
        return res
          .status(400)
          .send({ message: "Title, description, and authorName are required" });
      }

      try {
        const newAnnouncement = {
          title,
          description,
          authorName,
          authorImage,
          createdAt: new Date(),
        };

        const result = await db
          .collection("announcements")
          .insertOne(newAnnouncement);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        console.error("Failed to add announcement:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // GET /announcements — Get all announcements sorted by newest first
    app.get("/announcements", async (req, res) => {
      try {
        const announcements = await db
          .collection("announcements")
          .find()
          .sort({ createdAt: -1 })
          .toArray();

        res.send(announcements);
      } catch (err) {
        console.error("Failed to fetch announcements:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // GET /notifications?userEmail=user@example.com
    app.get("/notifications", async (req, res) => {
      const { userEmail } = req.query;
      if (!userEmail)
        return res.status(400).send({ message: "Missing userEmail" });

      try {
        const notifications = await db
          .collection("notifications")
          .find({ userEmail })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(notifications);
      } catch (err) {
        console.error("❌ Failed to fetch notifications:", err);
        res.status(500).send({ message: "Failed to fetch notifications" });
      }
    });

    app.post("/notifications", async (req, res) => {
      const { userEmail, type, message } = req.body;
      if (!userEmail || !type || !message) {
        return res.status(400).send({ message: "Missing notification data" });
      }
      try {
        const result = await db.collection("notifications").insertOne({
          userEmail,
          type,
          message,
          isRead: false,
          createdAt: new Date(),
        });
        res.send({
          success: true,
          message: "Notification sent",
          insertedId: result.insertedId,
        });
      } catch (err) {
        console.error("❌ Failed to send notification:", err);
        res.status(500).send({ message: "Failed to send notification" });
      }
    });

    // PATCH all notifications as read
    app.patch("/notifications/mark-read", async (req, res) => {
      const { userEmail } = req.body;

      if (!userEmail)
        return res.status(400).send({ message: "Missing userEmail" });

      try {
        await db
          .collection("notifications")
          .updateMany({ userEmail }, { $set: { isRead: true } });
        res.send({ success: true });
      } catch (err) {
        console.error("❌ Failed to mark notifications read:", err);
        res.status(500).send({ message: "Failed to mark read" });
      }
    });

    app.get("/notifications/archive", async (req, res) => {
      const { userEmail } = req.query;
      if (!userEmail)
        return res.status(400).send({ message: "Missing userEmail" });

      try {
        const archived = await db
          .collection("notificationArchive")
          .find({ userEmail })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(archived);
      } catch (err) {
        console.error("❌ Failed to fetch archived notifications:", err);
        res
          .status(500)
          .send({ message: "Failed to fetch archived notifications" });
      }
    });

    app.get("/notifications/archive-all", async (req, res) => {
      try {
        const archived = await db
          .collection("notificationArchive")
          .find()
          .sort({ createdAt: -1 })
          .toArray();

        res.send(archived);
      } catch (err) {
        console.error("❌ Failed to fetch all archived notifications:", err);
        res
          .status(500)
          .send({ message: "Failed to fetch archived notifications" });
      }
    });

    //  Move all user's notifications to archive & clear active
    app.post("/notifications/archive", async (req, res) => {
      const { userEmail } = req.body;

      if (!userEmail)
        return res.status(400).send({ message: "Missing userEmail" });

      try {
        const notifications = await db
          .collection("notifications")
          .find({ userEmail })
          .toArray();

        if (notifications.length === 0) {
          return res.send({ message: "No notifications to archive" });
        }

        // Step 1: Insert into archive
        await db.collection("notificationArchive").insertMany(notifications);

        // Step 2: Remove from main collection
        await db.collection("notifications").deleteMany({ userEmail });

        res.send({
          success: true,
          message: "Notifications archived and cleared",
        });
      } catch (err) {
        console.error("❌ Failed to archive notifications:", err);
        res.status(500).send({ message: "Failed to archive notifications" });
      }
    });

    // DELETE /notifications/archive/:id - Delete archived notification by _id
    app.delete("/notifications/archive/:id", async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid notification ID" });
      }

      try {
        const result = await db
          .collection("notificationArchive")
          .deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) {
          return res.status(404).send({ message: "Notification not found" });
        }

        res.send({ success: true, message: "Notification deleted" });
      } catch (err) {
        console.error("❌ Delete notification error:", err);
        res.status(500).send({ message: "Failed to delete notification" });
      }
    });

    //  Get All Membership Plans
    app.get("/membershipplans", async (req, res) => {
      try {
        const plans = await db.collection("membershipplans").find().toArray();
        res.send(plans);
      } catch (err) {
        console.error("❌ Failed to fetch membership plans:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    //  Get Membership Plan by ID
    app.get("/membershipplans/:id", async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid membership plan ID" });
      }

      try {
        const plan = await db
          .collection("membershipplans")
          .findOne({ _id: new ObjectId(id) });

        if (!plan) {
          return res.status(404).send({ message: "Membership plan not found" });
        }

        res.send(plan);
      } catch (err) {
        console.error("❌ Failed to fetch membership plan:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    //  Get Payment History (All or by Email)
    app.get("/payments", async (req, res) => {
      const email = req.query.email;

      try {
        const filter = email ? { userEmail: email } : {};

        const history = await db
          .collection("payments")
          .find(filter)
          .sort({ paidAt: -1 })
          .toArray();

        res.send(history);
      } catch (err) {
        console.error("❌ Error loading payment history:", err);
        res.status(500).send({ message: "Failed to fetch payment history" });
      }
    });

    //  Save Payment & Update User Badge
    app.post("/payments", async (req, res) => {
      const {
        userEmail,
        userId,
        planId,
        planTitle,
        amount,
        currency,
        transactionId,
      } = req.body;

      if (
        !userEmail ||
        !userId ||
        !planId ||
        !amount ||
        !currency ||
        !planTitle
      ) {
        return res.status(400).send({ message: "Missing payment data" });
      }

      try {
        //  Save to payments collection
        const paymentDoc = {
          userEmail,
          userId,
          planId: new ObjectId(planId),
          planTitle,
          amount,
          currency,
          transactionId: transactionId || null,
          paidAt: new Date(),
        };

        await db.collection("payments").insertOne(paymentDoc);
        const updateResult = await userCollection.updateOne(
          { uid: userId },
          { $set: { badge: "Gold" } }
        );

        if (updateResult.modifiedCount === 0) {
          return res.status(404).send({ message: "Membership plan not found" });
        }

        res.send({ success: true, message: "Payment saved and user updated" });
      } catch (err) {
        console.error("❌ Payment error:", err);
        res.status(500).send({ message: "Failed to save payment info" });
      }
    });

    app.post("/create-payment-intent", async (req, res) => {
      const amountInCents = req.body.amountInCents;
      try {
        const paymentIntent = await stripe.paymentIntents.create({
          amount: amountInCents,
          currency: "usd",
          payment_method_types: ["card"],
        });

        res.json({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Base route
    app.get("/", (req, res) => {
      res.send("CodeCircle API is live!");
    });

    app.listen(port, () => {
      console.log(`⚡ Server running on http://localhost:${port}`);
    });
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err);
  }
}

run().catch(console.dir);
