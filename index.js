const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(token, "your_jwt_secret", (err, user) => {
    if (err)
      return res.status(403).json({ message: "Token expired or invalid" });
    req.user = user; // Add user details to request
    next();
  });
}

app.get("/protected-route", authenticateToken, (req, res) => {
  res.json({ message: "Access granted", user: req.user });
});

// Database connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB "))
  .catch((err) => console.error("Error connecting to MongoDB:", err));

// Product Schema and Model
const productSchema = new mongoose.Schema({
  productId: String,
  name: String,
  description: String,
  category: String, // Add this Field
  subcategory: String,
  diamondColor: String,
  numberOfDiamond: Number,
  diamondCutGrade: String,
  diamondShape: String,
  diamondType: String,
  sideDiamondColor: String,
  numberOfSideDiamond: Number,
  sideDiamondShape: String,
  sideDiamondCutGrade: String,
  sideDiamondType: String,
  stoneColor: String,
  stoneType: String,
  stoneWeight: Number,
  stoneShape: String,
  images: {
    gold: [String],
    roseGold: [String],
    silver: [String],
    hover: String,
  },
  availableColors: [String],
  availableKarats: [String],
  availableStones: [String],
  weight: { type: Number },
  diamondPrice: { type: Number },
  diamondWeight: { type: Number },
  sideDiamondWeight: { type: Number },
  stonePieces: { type: Number },
  stonePrice: { type: Number },
  makingCharge: { type: Number },
  discount: { type: Number },
  prices: {
    tenK: Number,
    fourteenK: Number,
    eighteenK: Number,
  },
  discountedPrice: {
    tenK: Number,
    fourteenK: Number,
    eighteenK: Number,
  },
});

const Product = mongoose.model("Product", productSchema);


// User Schema
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String,
  token: { type: String },
  status: { type: String, default: "Active" }, // Add status field
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);

// Wishlist Schema and Model
const wishlistSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Product",
    required: true,
  },
});

const Wishlist = mongoose.model("Wishlist", wishlistSchema);

// Multer Storage Configuration
// Multer Storage Configuration (Move it here, before any routes use it)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage });

// Return Order Schema
const returnOrderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: "User" },
  reason: { type: String, required: true },
  proofImage: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ["Pending", "Accept", "Reject"], default: "Pending" },
  createdAt: { type: Date, default: Date.now },
});


const ReturnOrder = mongoose.model("ReturnOrder", returnOrderSchema);

// Return Order Router (Now upload is defined before it's used)
const returnOrderRouter = express.Router();

returnOrderRouter.post("/submit", upload.single("proofImage"), async (req, res) => {
  try {
    const { userId, reason, email, phone, amount } = req.body;
    const proofImage = req.file ? req.file.filename : null;

    if (!userId || !reason || !proofImage || !email || !phone || !amount) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const returnOrder = new ReturnOrder({
      userId,
      reason,
      proofImage,
      email,
      phone,
      amount,
    });

    await returnOrder.save();
    res.status(201).json({ message: "Return order submitted successfully" });
  } catch (error) {
    console.error("Error submitting return order:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Use the return order router
app.use("/return-orders", returnOrderRouter);

returnOrderRouter.put("/:id", async (req, res) => {
  try {
    const { status } = req.body;
    const updatedOrder = await ReturnOrder.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    res.json(updatedOrder);
  } catch (error) {
    res.status(500).json({ message: "Error updating order status" });
  }
});

returnOrderRouter.get("/", async (req, res) => {
  try {
    const orders = await ReturnOrder.find();
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: "Error fetching return orders" });
  }
});


// Mock user middleware for testing
app.use((req, res, next) => {
  req.user = { _id: "64b6a1d8e4b6a23f8f4b6a5e" }; // Replace with a valid user ID
  next();
});

// Categories Data
const categoriesData = {
  trending: ["Trending", "New Arrivals", "Best Sellers"],
  earrings: ["Earrings", "Studs", "Drops", "Jhumkas"],
  rings: ["Rings", "Wedding Bands", "Cocktail Rings"],
  necklaces: ["Necklaces", "Chokers", "Pendants"],
  bracelets: ["Bracelets", "Charm Bracelets", "Bangles"],
  gifts: ["Gifts", "Birthday", "Festive"],
};

// Categories Route

app.get("/api/categories", (req, res) => {
  res.json(categoriesData);
});

// Add a New Product
app.post(
  "/api/products",
  upload.fields([
    { name: "goldImage", maxCount: 30 },
    { name: "roseGoldImage", maxCount: 30 },
    { name: "silverImage", maxCount: 30 },
    { name: "hoverImage", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      console.log("Request body:", req.body);
      console.log("Uploaded files:", req.files);

      const {
        productId,
        name,
        weight,
        price10k,
        price14k,
        price18k,
        discountedPrice10k,
        discountedPrice14k,
        discountedPrice18k,
        availableKarats,
        availableStones,
        description,
        diamondColor,
        numberOfDiamond,
        diamondCutGrade,
        diamondShape,
        diamondType,
        sideDiamondColor,
        numberOfSideDiamond,
        sideDiamondShape,
        sideDiamondCutGrade,
        sideDiamondType,
        stonePieces,
        stoneColor,
        stoneShape,
        stoneWeight,
        stoneType,
        category,
        subcategory, // Add this field
      } = req.body;

      const karatPrices = await KaratPrice.find({});
      if (!karatPrices || karatPrices.length === 0) {
        return res.status(500).json({ error: "Karat prices not found" });
      }

      const images = {
        gold: req.files.goldImage?.map((file) => file.path) || [],
        roseGold: req.files.roseGoldImage?.map((file) => file.path) || [],
        silver: req.files.silverImage?.map((file) => file.path) || [],
        hover: req.files.hoverImage?.[0]?.path || "",
      };

      const newProduct = new Product({
        productId,
        name,
        description,
        category,
        subcategory, // Add this field
        diamondColor,
        numberOfDiamond,
        diamondCutGrade,
        diamondShape,
        diamondType,
        sideDiamondColor,
        numberOfSideDiamond,
        sideDiamondShape,
        sideDiamondCutGrade,
        sideDiamondType,
        stonePieces,
        stoneColor,
        stoneShape,
        stoneWeight,
        stoneType,
        images,
        availableColors: ["gold", "roseGold", "silver"],
        weight,
        prices: {
          tenK: parseFloat(price10k),
          fourteenK: parseFloat(price14k),
          eighteenK: parseFloat(price18k),
        },
        discountedPrice: {
          tenK: parseFloat(discountedPrice10k),
          fourteenK: parseFloat(discountedPrice14k),
          eighteenK: parseFloat(discountedPrice18k),
        },
        availableKarats: JSON.parse(availableKarats),
        availableStones: JSON.parse(availableStones),
      });

      await newProduct.save();
      res.status(201).json(newProduct);
    } catch (error) {
      console.error("Error while creating product:", error);
      res.status(500).json({ error: "Failed to create product" });
    }
  }
);

// Fetch All Products

app.get("/api/products", async (req, res) => {
  try {
    const { category, subcategory } = req.query;

    let query = {};
    if (category) query.category = category;
    if (subcategory) query.subcategory = subcategory;

    const products = await Product.find(query);
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch products", error });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: "Product not found" });
  }
});

// Wishlist Routes

// Get user's wishlist

app.get("/api/wishlist", async (req, res) => {
  try {
    const userId = req.user._id;

    const wishlist = await Wishlist.find({ userId }).populate({
      path: "productId",
      select: "name images",
    });

    res.json(
      wishlist.map((item) => {
        const product = item.productId;
        return {
          _id: item._id,
          name: product.name,
          image: product.images?.gold?.[0] || "/default.jpg",
        };
      })
    );
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch wishlist", error });
  }
});




// Add to wishlist

app.post("/api/wishlist", async (req, res) => {
  try {
    const { productId } = req.body;
    const userId = req.user._id;

    const existingItem = await Wishlist.findOne({ userId, productId });
    if (existingItem) {
      return res.status(400).json({ message: "Already in wishlist" });
    }

    const newItem = new Wishlist({ userId, productId });
    await newItem.save();

    res.status(201).json({ message: "Added to wishlist", newItem });
  } catch (error) {
    res.status(500).json({ message: "Failed to add to wishlist", error });
  }
});


app.delete("/api/wishlist/:id", async (req, res) => {
  try {
    const userId = req.user._id;
    const { id } = req.params;

    const item = await Wishlist.findOneAndDelete({ _id: id, userId });
    if (!item) return res.status(404).json({ message: "Item not found" });

    res.json({ message: "Removed from wishlist" });
  } catch (error) {
    res.status(500).json({ message: "Failed to remove from wishlist", error });
  }
});


const karatPriceSchema = new mongoose.Schema({
  karat: { type: String, required: true, unique: true },
  price: { type: String, required: true },
});

const KaratPrice = mongoose.model("KaratPrice", karatPriceSchema);

const initializeKaratPrices = async () => {
  const count = await KaratPrice.countDocuments();

  if (count === 0) {
    const initialPrices = [
      { karat: "10K", price: "00.00" },
      { karat: "14K", price: "00.00" },
      { karat: "18K", price: "00.00" },
    ];

    await KaratPrice.insertMany(initialPrices);
    console.log("Initialized karat prices with default values.");
  } else {
    console.log("Karat prices already initialized, skipping.");
  }
};

initializeKaratPrices();

app.put("/api/karat-prices", async (req, res) => {
  try {
    const { karat, price } = req.body;

    if (!karat || !price) {
      return res.status(400).json({ message: "Karat and price are required" });
    }

    const updatedPrice = await KaratPrice.findOneAndUpdate(
      { karat },
      { price },
      { new: true, upsert: true }
    );

    res.json(updatedPrice);
  } catch (error) {
    res.status(500).json({ message: "Failed to update karat price.", error });
  }
});

app.get("/api/karat-prices", async (req, res) => {
  try {
    const prices = await KaratPrice.find({});
    res.json(prices);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch karat prices", error });
  }
});

// Register Route
app.post("/register", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "User already exists." });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({
    firstName,
    lastName,
    email,
    password: hashedPassword,
    status: "Active", // Default status is Active
  });

  await newUser.save();
  res.status(201).json({ message: "User registered successfully" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: "Please register first" });
  }

  if (user.status === "Inactive") {
    return res
      .status(403)
      .json({ message: "Your account is inactive. Please contact support." });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign({ userId: user._id }, "your_jwt_secret", {
    expiresIn: "365d",
  });

  user.token = token;
  await user.save();

  res.status(200).json({
    message: "Login successful",
    token,
    firstName: user.firstName,
    userId: user._id,
  });
});

app.get("/users", async (req, res) => {
  try {
    const users = await User.find(
      {},
      "firstName lastName email createdAt status"
    ); // Fetch relevant fields
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/users/:id/status", async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.status = user.status === "Active" ? "Inactive" : "Active";
    await user.save();

    res
      .status(200)
      .json({ message: "User status updated", status: user.status });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Define Cart schema
const cartSchema = new mongoose.Schema({
  userId: { type: String, required: true }, // Associate cart with a user
  quantity: { type: Number, required: true },
  productId: String,
  name: String,
  color: String,
  size: String,
  karat: String,
  stone: String,
  price: String,
  originalPrice: String,
  image: String,
});

const Cart = mongoose.model("Cart", cartSchema);

// Add item to cart
app.post("/api/cart", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token)
      return res.status(401).json({ message: "Unauthorized: Please log in" });

    const decoded = jwt.verify(token, "your_jwt_secret");
    const userId = decoded.userId;

    const {
      productId,
      name,
      color,
      size,
      karat,
      stone,
      price,
      originalPrice,
      image,
      quantity,
    } = req.body;

    const newCartItem = new Cart({
      userId,
      productId,
      name,
      color,
      size,
      karat,
      stone,
      price,
      originalPrice,
      image,
      quantity,
    });

    await newCartItem.save();
    res.status(200).json({ message: "Product added to cart" });
  } catch (error) {
    console.error("Error adding to cart:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/cart", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Unauthorized: Please log in" });
    }

    const decoded = jwt.verify(token, "your_jwt_secret"); // Ensure the secret matches
    console.log("Decoded token:", decoded); // Log the token to confirm userId
    const userId = decoded.userId;

    const cartItems = await Cart.find({ userId });
    res.status(200).json(cartItems);
  } catch (error) {
    console.error("Error fetching cart items:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/cart", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token)
      return res.status(401).json({ message: "Unauthorized: Please log in" });

    const decoded = jwt.verify(token, "your_jwt_secret");
    const userId = decoded.userId;

    await Cart.deleteMany({ userId }); // Deletes all cart items for the user

    res.status(200).json({ message: "Cart cleared successfully" });
  } catch (error) {
    console.error("Error clearing cart:", error);
    res.status(500).json({ message: "Server error" });
  }
});


app.put("/api/cart/:id", async (req, res) => {
  try {
    const { quantity } = req.body;
    const itemId = req.params.id;

    if (!quantity || quantity < 1) {
      return res.status(400).json({ message: "Invalid quantity" });
    }

    const updatedItem = await Cart.findByIdAndUpdate(
      itemId,
      { $set: { quantity } },
      { new: true }
    );

    if (!updatedItem) {
      return res.status(404).json({ message: "Item not found" });
    }

    res.json(updatedItem);
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

const OrderSchema = new mongoose.Schema({
  userId: { type: String, required: true }, // ✅ Add userId
  email: String,
  firstName: String,
  lastName: String,
  address: String,
  country: String,
  state: String,
  city: String,
  pincode: String,
  phone: String,
  cartItems: [
    {
      name: String,
      color: String,
      size: String,
      karat: String,
      stone: String,
      quantity: Number,
      price: Number,
      image: String,
    },
  ],
  totalAmount: Number,
  status: { type: String, default: "pending" },
  createdAt: { type: Date, default: Date.now },
});

const Order = mongoose.model("Order", OrderSchema);

// Get orders for a user
app.get("/orders/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    // Find user by userId
    const user = await User.findById(userId);
    if (!user || !user.token) {
      return res.status(401).json({ message: "Unauthorized: Token not found" });
    }

    // Find orders for the user
    const orders = await Order.find({ userId });

    res.status(200).json({ orders, token: user.token });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

app.get("/get-user", async (req, res) => {
  try {
    // Assuming userId is already stored in the backend
    const user = await User.findOne(); // Adjust this query as needed

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ userId: user._id, token: user.token });
  } catch (error) {
    console.error("Error in /get-user:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/get-token/:userId", async (req, res) => {
  const { userId } = req.params;
  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: "User not found" });

  res.json({ token: user.token });
});

app.post("/orders", async (req, res) => {
  try {
    const {
      userId,
      email,
      firstName,
      lastName,
      address,
      country,
      state,
      city,
      pincode,
      phone,
      cartItems,
      totalAmount,
    } = req.body;

    if (!userId) {
      return res.status(400).json({ message: "User ID is required" });
    }

    const order = new Order({
      userId,
      email,
      firstName,
      lastName,
      address,
      country,
      state,
      city,
      pincode,
      phone,
      cartItems,
      totalAmount,
      status: "pending",
    });

    await order.save();
    res.status(201).json({ message: "Order placed successfully", order });
  } catch (error) {
    console.error("Error saving order:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/orders", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, "your_jwt_secret");
    const userId = decoded.userId;

    // Get status from query params
    const status = req.query.status;
    const query = { userId };

    if (status) query.status = status; // Apply status filter if provided

    const orders = await Order.find(query);
    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.put("/orders/:orderId/status", async (req, res) => {
  const { orderId } = req.params;
  const { status } = req.body;

  try {
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Log before updating the order
    console.log(`Updating order ${orderId} status to ${status}`);

    order.status = status;
    await order.save();

    res.status(200).json(order);
  } catch (error) {
    console.error("Error updating order status:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
