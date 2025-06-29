const mongoose = require('mongoose');
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const pdfParse = require('pdf-parse');
const hljs = require('highlight.js');

const genAI = new GoogleGenerativeAI('AIzaSyDJE2q9x7xugJEFUGZT2REg0CKZ2hWX0_w'); // Replace with your actual key

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.json());

app.use(session({
    secret: 'yourSecretKey',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        sameSite: 'lax'
    }
}));


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Error:", err));

  const importantDateSchema = new mongoose.Schema({
  userEmail: String,
  fileId: { type: mongoose.Schema.Types.ObjectId, ref: 'File' }, // ✅ this is important
  date: String,
  description: String
});


const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});
const User = mongoose.model('User', userSchema);

const fileSchema = new mongoose.Schema({
    userEmail: String,
    userName: String,
    originalname: String,
    filename: String,
    type: String,
    size: Number,
    uploadDate: { type: Date, default: Date.now }
});
const File = mongoose.model('File', fileSchema);

const pdfKnowledgeSchema = new mongoose.Schema({
    userEmail: String,
    fileId: { type: mongoose.Schema.Types.ObjectId, ref: 'File' }, // added ref
    content: String
});

const PdfKnowledge = mongoose.model('PdfKnowledge', pdfKnowledgeSchema);


const sharedFileSchema = new mongoose.Schema({
    senderEmail: String,
    senderName: String,
    recipientEmail: String,
    recipientName: String,
    originalname: String,
    filename: String,
    type: String,
    size: Number,
    uploadDate: { type: Date, default: Date.now }
});
const SharedFile = mongoose.model('SharedFile', sharedFileSchema);

const FILE_UPLOAD_PATH = path.join('/tmp', 'uploads');

app.use('/uploads', express.static(FILE_UPLOAD_PATH));

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userFolder = path.join(FILE_UPLOAD_PATH, req.session.user.email);
        fs.mkdirSync(userFolder, { recursive: true });
        cb(null, userFolder);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage });
const formParser = multer();

app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    next();
});

function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/login');
}

app.get('/', (req, res) => res.render('home', { error: null, name: req.session.user ? req.session.user.name : "Guest" }));

app.get('/home', (req, res) => {
    const username = req.session.user ? req.session.user.name : "Guest";
    res.render('home', { error: null, name: username });
});

app.get('/login', (req, res) => res.render('login', { error: null }));

app.get('/signup', (req, res) => res.render('signup', { error: null }));

app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) {
        return res.render('signup', { error: "User already exists" });
    }
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?#&_])[A-Za-z\d@$!%*?#&_]{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.render('signup', {
            error: "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character."
        });
    }
    const newUser = new User({ name, email, password });
    await newUser.save();
    res.render('login', { error: "Signup successful. Please login." });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const existing = await User.findOne({ email });
    if (!existing) return res.render('login', { error: "User does not exist" });
    if (existing.password !== password)
        return res.render('login', { error: "Incorrect password" });
    req.session.user = existing;
    res.redirect('/afterlogin');
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.send("Logout failed");
        res.redirect('/home');
    });
});

app.get('/afterlogin', isAuthenticated, async (req, res) => {
    const userEmail = req.session.user.email;
    const query = req.query.q ? req.query.q.trim() : "";
    let files = await File.find({ userEmail });
    if (query) {
        files = files.filter(file =>
            file.originalname.toLowerCase().includes(query.toLowerCase())
        );
    }
    const MAX_STORAGE = 5 * 1024 * 1024 * 1024; // 5GB
    const usage = { pdf: 0, docs: 0, ppts: 0, photos: 0, videos: 0, others: 0, total: 0, free: 0 };
    files.forEach(file => {
        const type = file.type || "";
        const name = file.originalname.toLowerCase();
        const size = file.size;
        if (type.includes("pdf")) usage.pdf += size;
        else if (type.includes("word") || name.endsWith(".doc") || name.endsWith(".docx")) usage.docs += size;
        else if (name.endsWith(".ppt") || name.endsWith(".pptx")) usage.ppts += size;
        else if (type.startsWith("image/")) usage.photos += size;
        else if (type.startsWith("video/")) usage.videos += size;
        else usage.others += size;
        usage.total += size;
    });
    usage.free = MAX_STORAGE - usage.total;
    const usageData = {
        "PDF & Docs": usage.pdf + usage.docs + usage.others,
        "PPTX Files": usage.ppts,
        "Media Files": usage.photos + usage.videos,
        "Free Space": usage.free
    };
    res.render('afterlogin', {
    name: req.session.user.name,
    files,
    usage,
    maxStorage: MAX_STORAGE,
    usageData,
    query,
    summary: null, // ✅ Add this
    error:null
});

});
// GET /search?q=query
app.get('/search', async (req, res) => {
    const q = req.query.q?.toLowerCase() || '';
    const files = await File.find({
        originalname: { $regex: q, $options: 'i' }
    }).lean();
    res.json(files);
});

app.get('/files', isAuthenticated, async (req, res) => {
    const files = await File.find({ userEmail: req.session.user.email });
    const MAX_STORAGE = 5 * 1024 * 1024 * 1024; // 5GB
    const usage = { pdf: 0, docs: 0, ppts: 0, photos: 0, videos: 0, others: 0, total: 0, free: 0 };
    files.forEach(file => {
        const ext = file.originalname.toLowerCase();
        if (file.type.includes("pdf")) usage.pdf += file.size;
        else if (file.type.includes("word") || ext.endsWith(".docx") || ext.endsWith(".txt")) usage.docs += file.size;
        else if (ext.endsWith(".ppt") || ext.endsWith(".pptx")) usage.ppts += file.size;
        else if (file.type.startsWith("image/")) usage.photos += file.size;
        else if (file.type.startsWith("video/")) usage.videos += file.size;
        else usage.others += file.size;
    });
    usage.total = usage.pdf + usage.docs + usage.ppts + usage.photos + usage.videos + usage.others;
    usage.free = MAX_STORAGE - usage.total;
    const getWidthClass = (val) => {
        const percent = ((val / MAX_STORAGE) * 100).toFixed(2);
        return `w-[${percent}%]`;
    };
    const widthClasses = {
        pdf: getWidthClass(usage.pdf + usage.docs + usage.others),
        ppts: getWidthClass(usage.ppts),
        media: getWidthClass(usage.photos + usage.videos),
        free: getWidthClass(usage.free)
    };
    // Suggest files: Small, old, or unknown type
const suggestedFiles = files.filter(file => {
    const ext = file.originalname.toLowerCase();
    const ageInDays = (Date.now() - new Date(file.uploadDate).getTime()) / (1000 * 60 * 60 * 24);

    return (
        file.size < 100 * 1024 ||                     // Less than 100KB
        (!file.type || file.type === 'application/octet-stream') || // Unknown type
        ageInDays > 30                               // Older than 6 months
    );
});



res.render('files', {
    error: null,
    name: req.session.user.name,
    files,
    usage,
    maxStorage: MAX_STORAGE,
    widthClasses,
    suggestedFiles
});


});
app.post('/summarize', isAuthenticated, async (req, res) => {
    try {
        const userEmail = req.session.user.email;
        const userName = req.session.user.name;

        // Fetch user's PDF knowledge from database
        const pdfs = await PdfKnowledge.find({ userEmail });

        if (!pdfs.length) {
            return res.render('afterlogin', {
                name: userName,
                files: await File.find({ userEmail }),
                usage: {}, usageData: {}, maxStorage: 0, query: "",
                summary: "No documents found for summarization."
            });
        }

        const combinedText = pdfs.map(doc => doc.content).join('\n').slice(0, 30000); // limit size

        const prompt = `
You are a document summarizer. Summarize the following content briefly in bullet points or short paragraphs.

"""
${combinedText}
"""
`;

        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        const result = await model.generateContent(prompt);
        const text = await result.response.text();

        // Get file usage stats (same as in /afterlogin)
        const files = await File.find({ userEmail });
        const MAX_STORAGE = 5 * 1024 * 1024 * 1024;
        const usage = { pdf: 0, docs: 0, ppts: 0, photos: 0, videos: 0, others: 0, total: 0 };
        files.forEach(file => {
            const type = file.type || "";
            const name = file.originalname.toLowerCase();
            const size = file.size;
            if (type.includes("pdf")) usage.pdf += size;
            else if (type.includes("word") || name.endsWith(".doc") || name.endsWith(".docx")) usage.docs += size;
            else if (name.endsWith(".ppt") || name.endsWith(".pptx")) usage.ppts += size;
            else if (type.startsWith("image/")) usage.photos += size;
            else if (type.startsWith("video/")) usage.videos += size;
            else usage.others += size;
            usage.total += size;
        });

        const usageData = {
            "PDF & Docs": usage.pdf + usage.docs + usage.others,
            "PPTX Files": usage.ppts,
            "Media Files": usage.photos + usage.videos,
            "Free Space": MAX_STORAGE - usage.total
        };

        // Render afterlogin with the summary
        res.render('afterlogin', {
            name: userName,
            files,
            usage,
            usageData,
            maxStorage: MAX_STORAGE,
            query: "",
            summary: text, // ✅ pass the summary to the view
            error:null
        });

    } catch (err) {
    console.error("Summarization Error:", err);

    const userEmail = req.session.user.email;
    const userName = req.session.user.name;
    const files = await File.find({ userEmail });
    
    const MAX_STORAGE = 5 * 1024 * 1024 * 1024;
    const usage = { pdf: 0, docs: 0, ppts: 0, photos: 0, videos: 0, others: 0, total: 0 };
    files.forEach(file => {
        const type = file.type || "";
        const name = file.originalname.toLowerCase();
        const size = file.size;
        if (type.includes("pdf")) usage.pdf += size;
        else if (type.includes("word") || name.endsWith(".doc") || name.endsWith(".docx")) usage.docs += size;
        else if (name.endsWith(".ppt") || name.endsWith(".pptx")) usage.ppts += size;
        else if (type.startsWith("image/")) usage.photos += size;
        else if (type.startsWith("video/")) usage.videos += size;
        else usage.others += size;
        usage.total += size;
    });

    const usageData = {
        "PDF & Docs": usage.pdf + usage.docs + usage.others,
        "PPTX Files": usage.ppts,
        "Media Files": usage.photos + usage.videos,
        "Free Space": MAX_STORAGE - usage.total
    };

    // ✅ Now include 'query' and 'summary' as null and an error message
    res.render('afterlogin', {
        name: userName,
        files,
        usage,
        usageData,
        maxStorage: MAX_STORAGE,
        query: "",
        summary: null,
        error: "You have hit the daily limit, please try after some time"
    });
}

});



app.get('/download/:filename', isAuthenticated, (req, res) => {
    const userEmail = req.session.user.email;
    const filename = req.params.filename;
    const filePath = path.join(FILE_UPLOAD_PATH, userEmail, filename);
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) return res.status(404).send('File not found');
        res.download(filePath); // This forces file download
    });
});

app.post('/upload', isAuthenticated, upload.array('files'), async (req, res) => {
    const userEmail = req.session.user.email;
    const userName = req.session.user.name;
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

    for (const file of req.files) {
        const newFile = new File({
            userEmail,
            userName,
            originalname: file.originalname,
            filename: file.filename,
            type: file.mimetype,
            size: file.size
        });
        await newFile.save();

        // ✅ If PDF, extract text and store
        if (file.mimetype === "application/pdf") {
            const dataBuffer = fs.readFileSync(file.path);
            const pdfData = await pdfParse(dataBuffer);

            // ✅ Save content to PdfKnowledge
            await new PdfKnowledge({
                userEmail,
                fileId: newFile._id,
                content: pdfData.text
            }).save();

            // ✅ Log and call Gemini to extract dates
            console.log(`📢 Calling Gemini API for: ${file.originalname}`);
            const prompt = `
Below is the extracted content from a document:

"""
${pdfData.text.slice(0, 10000)}
"""

From the above content, extract all **important dates** and for each date, give:
1. The **exact date** in YYYY-MM-DD format
2. A **short title**
3. A **brief description** explaining why it is important

Respond in raw JSON array format like:
[
  {
    "date": "2025-06-24",
    "title": "Project Deadline",
    "description": "Final submission date for semester projects."
  }
]

Only return the JSON array. Do not include any text, explanation, or code block markers.
            `;

            try {
                const result = await model.generateContent(prompt);
                const text = await result.response.text();

                const clean = text.replace(/```json|```/g, '').trim();
                const dateArray = JSON.parse(clean);

                for (const d of dateArray) {
                    await ImportantDate.create({
  userEmail,
  fileId: newFile._id, // ✅ very important
  date: d.date,
  description: `${d.title}: ${d.description}`
});

                }

                console.log(`✅ Gemini API extracted ${dateArray.length} dates for ${file.originalname}`);
            } catch (err) {
                console.error(`❌ Gemini API failed for ${file.originalname}:`, err.message);
            }
        }
    }

    res.redirect('/afterlogin');
});

app.post('/delete-suggested', async (req, res) => {
  const fileIds = Array.isArray(req.body.fileIds)
    ? req.body.fileIds
    : [req.body.fileIds];

  try {
    await File.deleteMany({ _id: { $in: fileIds } });
    res.redirect('/files');
  } catch (err) {
    res.status(500).send("Error deleting suggested files");
  }
});



app.post('/delete/:id', isAuthenticated, async (req, res) => {
    const fileId = req.params.id;

    try {
        const file = await File.findById(fileId);

        if (!file || file.userEmail !== req.session.user.email) {
            return res.status(403).send('Unauthorized');
        }

        const filePath = path.join(FILE_UPLOAD_PATH, file.userEmail, file.filename);

        // Delete file from disk
        fs.unlink(filePath, (err) => {
            if (err) console.error("File deletion error:", err);
        });

        // Delete file record
        await File.deleteOne({ _id: fileId });

        // Delete related PDF content (used for AI)
        await PdfKnowledge.deleteMany({ fileId });

        // ✅ Delete related important dates
        await ImportantDate.deleteMany({ fileId });

        res.redirect('/afterlogin');
    } catch (err) {
        console.error("Deletion error:", err);
        res.status(500).send("Server Error");
    }
});

app.post('/delete-multiple', isAuthenticated, async (req, res) => {
    const fileIds = req.body.fileIds;

    if (!fileIds) return res.redirect('/afterlogin');

    const filesToDelete = Array.isArray(fileIds) ? fileIds : [fileIds];

    try {
        for (const id of filesToDelete) {
            const file = await File.findById(id);
            if (!file || file.userEmail !== req.session.user.email) continue;

            const filePath = path.join(FILE_UPLOAD_PATH, file.userEmail, file.filename);

            // Delete file from disk
            fs.unlink(filePath, (err) => {
                if (err) console.error("Failed to delete file:", err.message);
            });

            // Delete file record
            await File.deleteOne({ _id: id });

            // Delete related data
            await PdfKnowledge.deleteMany({ fileId: id });
            await ImportantDate.deleteMany({ fileId: id }); // ✅ Delete related dates
        }

        res.redirect('/afterlogin');
    } catch (err) {
        console.error("Bulk delete error:", err.message);
        res.status(500).send("Internal Server Error");
    }
});

app.get('/shared', isAuthenticated, async (req, res) => {
    const sharedFiles = await SharedFile.find({ recipientEmail: req.session.user.email });
    res.render('shared', { sharedFiles });
});

app.delete('/delete-shared/:id', async (req, res) => {
    try {
        await SharedFile.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.json({ ok: false, error: 'Failed to delete' });
    }
});

app.post('/share-multiple', isAuthenticated, formParser.none(), async (req, res) => {
    const { fileIds, recipientEmail } = req.body || {};
    if (!fileIds || !recipientEmail) {
        return res.json({ ok: false, error: 'Missing file IDs or recipient email' });
    }
    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) {
        return res.json({ ok: false, error: 'Recipient not found' });
    }
    const fileIdArray = fileIds.split(',');
    const filesToShare = await File.find({ _id: { $in: fileIdArray } });
    for (const file of filesToShare) {
        const sharedFile = new SharedFile({
            senderEmail: req.session.user.email,
            senderName: req.session.user.name,
            recipientEmail: recipient.email,
            recipientName: recipient.name,
            originalname: file.originalname,
            filename: file.filename,
            type: file.type,
            size: file.size
        });
        await sharedFile.save();
    }
    res.json({ ok: true });
});

// AI Chat
app.get('/aichat', isAuthenticated, (req, res) => {
    const chatHistory = req.session.chatHistory || [];
    const animate = req.session.animate || false;
    req.session.animate = false;
    res.render('aichat', {
        error: null,
        chatHistory,
        hasStartedChat: chatHistory.length > 0,
        animate
    });
});

app.post('/aichat', isAuthenticated, async (req, res) => {
    try {
        // ✅ Validate session and prompt
        const userEmail = req.session?.user?.email;
        const userPrompt = req.body?.prompt?.trim();

        if (!userEmail || !userPrompt) {
            return res.render('aichat', {
                error: "Missing user session or input prompt.",
                chatHistory: req.session.chatHistory || [],
                animate: false,
                hasStartedChat: req.session.chatHistory && req.session.chatHistory.length > 0
            });
        }

        // ✅ Fetch PDFs from MongoDB
        const pdfs = await PdfKnowledge.find({ userEmail });
        if (!pdfs.length) {
            return res.render('aichat', {
                error: "No uploaded documents found to reference.",
                chatHistory: req.session.chatHistory || [],
                animate: false,
                hasStartedChat: req.session.chatHistory && req.session.chatHistory.length > 0
            });
        }

        const combinedText = pdfs.map(doc => doc.content).join("\n").slice(0, 30000);

        // ✅ Build AI prompt
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        const chatPrompt = `
You are a helpful assistant. Based on the content below, answer the user's question clearly using:

• Numbered points (1. 2. 3.)
• Bullet points (•)
• Paragraphs with line breaks
• If code is needed, wrap it using triple backticks (\`\`\`) and specify the language

Here is the content:
"""
${combinedText}
"""

User's question:
"${userPrompt}"
        `;

        // ✅ Call Gemini
        const result = await model.generateContent(chatPrompt);
        const rawText = await result.response.text();

        // ✅ Parse with Markdown
        const { marked } = await import('marked');
        marked.setOptions({ breaks: true, gfm: true });

        const response = marked.parse(rawText);

        // ✅ Update session history
        if (!req.session.chatHistory) req.session.chatHistory = [];
        req.session.chatHistory.push({ prompt: userPrompt, answer: response });
        req.session.animate = true;

        // ✅ Redirect
        res.redirect('/aichat');
    } catch (err) {
        console.error("AI Chat Error:", err);

        let errMsg = "Something went wrong. Please try again.";
        if (err.message?.includes("429")) {
            errMsg = "You've hit the daily usage limit. Try again later.";
        } else if (err.message?.includes("ENOTFOUND") || err.message?.includes("fetch failed")) {
            errMsg = "AI service unreachable. Please check your internet or API config.";
        }

        res.render('aichat', {
            error: errMsg,
            currentPath: req.path,
            chatHistory: req.session.chatHistory || [],
            animate: false,
            hasStartedChat: req.session.chatHistory && req.session.chatHistory.length > 0
        });
    }
});


const ImportantDate = mongoose.model('ImportantDate', importantDateSchema);

// Important Dates (AI)

app.get('/important-dates', isAuthenticated, async (req, res) => {
    const userEmail = req.session.user.email;
    const userName = req.session.user.name;

    // Get uploaded files
    const files = await File.find({ userEmail });

    // Get all stored important dates for this user
    const allDates = await ImportantDate.find({ userEmail });

    // Group dates by file
    const documents = files.map(file => {
        const relatedDates = allDates
            .filter(d => d.fileId?.toString() === file._id.toString())
            .map(d => ({
                date: d.date,
                description: d.description
            }));

        return {
            filename: file.originalname,
            dates: relatedDates
        };
    });

    res.render('important-dates', { name: userName, documents });
});






const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log('Server running on http://localhost:' + PORT);
});
