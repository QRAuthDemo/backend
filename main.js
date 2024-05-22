import Fastify from 'fastify'
import { MongoClient } from "mongodb";
import fastifyCors from '@fastify/cors';
import qr from 'qr-image';
import jwt from 'jsonwebtoken';
import { authenticator } from 'otplib';


authenticator.options = { digits: 6 ,window:5};


// Connect to MongoDB

const mongo = new MongoClient('mongodb://root:L3ebIFaie9A64ao2FkEXDOGK@alvand.liara.cloud:31373/my-app?authSource=admin');

// Create a Fastify instance
const app = Fastify({
    logger: true
  })

// Define the authenticated route
app.get('/user/mobileNumber', async (request, reply) => {
    try {
        // Check if the user is authenticated
        if (!request.headers.authorization) {
            reply.status(401).send({ error: 'Unauthorized' });
            return;
        }
        // Verify the authentication token
        const token = request.headers.authorization.replace('Bearer ', '');
        const decodedToken = jwt.verify(token, 'my_secret_key');
        if (!decodedToken) {
            reply.status(401).send({ error: 'Unauthorized' });
            return;
        }
        // Get the mobileNumber from the decoded token
        const mobileNumber = decodedToken.userId;
        // Query the database to get the user's mobileNumber
        const user = await mongo.db("QRAuthDemo").collection("Users").findOne({ mobileNumber });
        // Return the mobileNumber
        reply.send({ mobileNumber: user.mobileNumber });
    } catch (error) {
        // Return an error response
        reply.status(500).send({ error: 'Internal Server Error' });
    }
});

// Define the create user route
app.post('/createUser', async (request, reply) => {
    try {
        const { mobileNumber, password } = request.body;
        const secret = createSecret();
        // Check if the user is authenticated
        if (!request.headers.authorization) {
            reply.status(401).send({ error: 'Unauthorized' });
            return;
        }
        // Verify the authentication token
        const token = request.headers.authorization.replace('Bearer ', '');
        const decodedToken = jwt.verify(token, 'my_secret_key');
        if (!decodedToken) {
            reply.status(401).send({ error: 'Unauthorized' });
            return;
        }
        // Save the user to the database
        await mongo.db("QRAuthDemo").collection("Users").insertOne({ mobileNumber, password, secret });
        reply.status(201).send({ message: 'User created successfully' });
    } catch (error) {
        // Return an error response
        reply.status(500).send({ error: 'Internal Server Error' });
    }
});
// Enable CORS for all routes
app.register(fastifyCors, {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE']
});
// Define the login route
app.post('/login', async (request, reply) => {
    try {
        

        const { mobileNumber, password } = request.body;

        // Perform authentication logic here
        const user = await mongo.db("QRAuthDemo").collection("Users").findOne({ mobileNumber });

        if (!user) {
            // Return an error response if user not found
            reply.status(401).send({ error: 'Invalid credentials' });
            return;
        }
        if (user.password !== password && !await verifyOtp(user.secret, password)) {

                // Return an error response if password is incorrect
                reply.status(401).send({ error: 'Invalid credentials' });
                return;
            
        }
        // Authentication successful

        let response = getLoginAnswer(mobileNumber, user.secret)
        reply.send( response );


    } catch (error) {
        // Return an error response
        console.log(error)
        reply.status(500).send({ error: 'Internal Server Error' });
    }
});

// Start the server
app.listen({ port: 3000, host: '0.0.0.0' }, (err) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log('Server running on port 3000');
});

// Function to create QR code PNG with given input
function createQRCode(input) {
    const qrCode = qr.imageSync(input, { type: 'png' }).toString('base64');
    return qrCode;
}

function getLoginAnswer(mobileNumber, secret) {

    const payload = { userId: mobileNumber };
    const secretKey = 'my_secret_key';
    const expiresIn = '1h';
    const authenticatorUrl = `otpauth://totp/QRAuthDemo:${mobileNumber}?secret=${secret}&issuer=QRAuthDemo`;
    const authenticatorQRCode = createQRCode(authenticatorUrl);

    const jwtToken = createJwtToken(payload, secretKey, expiresIn);

    return {
        message: 'Login successful',

        jwt: jwtToken,
        jwtqr: createQRCode(jwtToken),
        authenticatorqr: authenticatorQRCode };
}

function createSecret() {
    // only containing characters matching (A-Z, 2-7)
    const allowed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let secret = '';
    for (let i = 0; i < 32; i++) {
        secret += allowed.charAt(Math.floor(Math.random() * allowed.length));
    }
    return secret;
}

async function verifyOtp(secret, otp) {
    otp = otp.toString();
    while (otp.length < 6) {
        otp = '0' + otp;
    }
    const token = authenticator.generate(secret);
    return otp === token
}

// Function to create a JWT token
function createJwtToken(payload, secret, expiresIn) {
    return jwt.sign(payload, secret, { expiresIn });
}