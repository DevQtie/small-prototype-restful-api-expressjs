import { sql, poolPromise, poolPromiseLogs, poolPromise17 } from '../config/db.config.js';
import dotenv from 'dotenv'
import { createCipheriv, createDecipheriv } from 'crypto';
import fs from 'fs';
import path from 'path';
import sharp from 'sharp';

dotenv.config({ path: '.env' }); // Load environment variables

const algorithm = process.env.ALGORITHM;

const key = Buffer.from(process.env.CRYPTO_KEY, process.env.BASE_STRUCTURE); // Use a secure, pre-shared key
const iv_val = Buffer.from(process.env.CRYPTO_IV, process.env.BASE_STRUCTURE);  // Use a random IV

const API_KEY_1 = process.env.API_KEY1; // Store securely

// // Middleware to check API key
// const authenticate = (req, res, next) => {
//     const apiKey = req.headers[process.env.API_HEADER];
//     if (apiKey && apiKey === API_KEY) {
//         next();
//     } else {
//         res.status(401).json({ error: 'Unauthorized' });
//     }
// };//basic structure

/*

result.recordset instead of result response to client-side, use result only if necessary

*/

const authenticate = async (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    try {
        const { iv } = req.body;
        const encryptedData1 = req.headers[process.env.API_HEADER1];//for API_KEY1
        const encryptedData2_raw = req.headers[process.env.API_HEADER2];//for API_KEY2
        const API_KEY_2 = decrypt(encryptedData2_raw, iv);//Decrypt the header2
        const apiKey1 = decrypt(encryptedData1, iv);
        const apiKey2 = process.env.CRYPTO_IV;//cross-check the decrypted header2
        if (apiKey1 && apiKey1 === API_KEY_1 && API_KEY_2 && API_KEY_2 === apiKey2) {
            next();
        } else {
            res.status(401).json({ error: 'Unauthorized' });//modify the message only for testing DEFAULT: Unauthorized
            await logsErrorExceptions('authenticate, message: {Unauthorized}, IP: ' + ip);
        }
    } catch (err) {
        res.status(401).send({ error: "Unauthorized" });//modify the message only for testing DEFAULT: Unauthorized
        await logsErrorExceptions('authenticate: ' + err.message + '. IP: ' + ip);
    }
};//This is working, please don't modify the structure unless necessary.

// Encryption function // I am using this to encrypt some data, simply it is used depending on my use case
const encrypt = (text) => {
    const cipher = createCipheriv(algorithm, key, iv_val);
    let encrypted = cipher.update(text, process.env.ENCODING_STRUCTURE, process.env.ENCODING);
    encrypted += cipher.final(process.env.ENCODING);
    return {
        iv_val: iv_val.toString(process.env.ENCODING),
        encryptedData: encrypted,
    };
};

// Decryption function
const decrypt = (encryptedData, ivHex) => {
    const iv = Buffer.from(ivHex, process.env.ENCODING);
    const encryptedText = Buffer.from(encryptedData, process.env.ENCODING);
    const decipher = createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedText, process.env.ENCODING, process.env.ENCODING_STRUCTURE);
    decrypted += decipher.final(process.env.ENCODING_STRUCTURE);
    return decrypted;
};

function isValidJson(input) {
    try {
        JSON.parse(input);
        return true;
    } catch (e) {
        return false;
    }
}

// Assuming files is an array of file objects with binary img_data
const fileList = async function (files) {
    return await Promise.all(
        files.map(async (file) => {
            try {
                // Compress the image data using sharp
                const compressedImageBuffer = await sharp(file.img_data)
                    .png({ compressionLevel: 9, quality: 1, progressive: false }) // Adjust settings as needed for your image format 
                    .toBuffer();

                // Convert the compressed binary data to base64
                const compressedBase64 = compressedImageBuffer.toString('base64');

                return {
                    img_name: file.img_name,
                    dt_stamp: file.dt_stamp,
                    img_data: compressedBase64, // Use the compressed base64 data
                    file_size: compressedImageBuffer.length // Update file size after compression
                };
            } catch (error) {
                console.error(`Error compressing image ${file.img_name}:`, error);
                return {
                    img_name: file.img_name,
                    dt_stamp: file.dt_stamp,
                    img_data: null, // Or handle the error accordingly
                    file_size: file.file_size // Keep original size or set to null
                };
            }
        })
    );
};

/* START OF MICROSOFT SQL SERVER 2017 */

const logsErrorExceptions = async (err) => {
    // Convert the error object to a string representation
    const error_exc_logs = JSON.stringify(err);
    const pool = await poolPromise17;
    const request = pool.request();

    try {
        await request.input('error_exc_logs', sql.NVarChar(sql.MAX), error_exc_logs)
            .query('EXEC rpiAPSM_spAPIErrExpLogs @error_exc_logs');
        //console.error('SuccessErrorLogging');//for testing purposes
    } catch (err2) {
        res.status(500).send({ message: err.message });
        // await logsErrorExceptions(err2.message);
        // console.error('UnsuccessErrorLogging');//for testing purposes
    }
}//system-level process only

// Example function to fetch data from MSSQL using stored procedure
const fetchData = async (req, res) => {
    try {
        const pool = await poolPromise17;
        const result = await pool.request().query('EXEC rpiAPSM_spRandomText'); // Replace with your stored procedure name
        res.json(result.recordset);
    } catch (err) {
        res.status(500).send({ message: err.message });
        await logsErrorExceptions('fetchData: ' + err.message);
    }
};//working&tested

const getRandomText = async (req, res) => {
    const { id } = req.params;

    try {
        const pool = await poolPromise17;
        const result = await pool.request()
            .input('id', sql.Int, id)
            .query('SELECT * FROM rpiAPSM_RandomText WHERE id = @id');

        if (result.recordset.length > 0) {
            res.json(result.recordset[0]);
        } else {
            res.status(404).send({ message: 'RandomText not found' });
        }
    } catch (err) {
        res.status(500).send({ message: err.message });
        await logsErrorExceptions('getRandomText: ' + err.message);
    }
}//working&tested

const addRandomText = async (req, res) => {
    const { random_text } = req.params;

    try {
        const pool = await poolPromise17;
        const request = pool.request();
        await request.input('random_text', sql.VarChar(50), random_text)
            .query('INSERT INTO rpiAPSM_RandomText (random_text) VALUES (@random_text)');
        res.status(201).send({ message: 'RandomText added successfully' });
    } catch (err) {
        res.status(500).send({ message: err.message });
        await logsErrorExceptions('addRandomText: ' + err.message);
    }
}//working&tested

const updateRandomText = async (req, res) => {
    const { id, random_text } = req.params;

    try {
        const pool = await poolPromise17;
        const request = pool.request();
        await request.input('id', sql.Int, id)
            .input('random_text', sql.VarChar(50), random_text)
            .query('UPDATE rpiAPSM_RandomText SET random_text = @random_text WHERE id = @id');
        res.status(200).send({ message: 'RandomText updated successfully' });
    } catch (err) {
        res.status(500).send({ message: err.message });
        await logsErrorExceptions('updateRandomText: ' + err.message);
    }
}//working&tested

const deleteRandomText = async (req, res) => {
    const { id } = req.params;

    try {
        const pool = await poolPromise17;
        const request = pool.request();
        await request.input('id', sql.Int, id)
            .query('DELETE FROM rpiAPSM_RandomText WHERE id = @id');
        res.status(200).send({ message: 'RandomText deleted successfully' });
    } catch (err) {
        res.status(500).send({ message: err.message });
        await logsErrorExceptions('deleteRandomText: ' + err.message);
    }
}//working&tested

/* END OF MICROSOFT SQL SERVER 2017 */

/* START OF MICROSOFT SQL SERVER 2008 R2 */

const signIn = async (req, res) => {
    const { comp_email, password, is_using_google } = req.body;

    try {
        const pool = await poolPromise;
        const request = pool.request();
        const result = await request.input('comp_email', sql.NVarChar(254), comp_email ?? null)
            .input('password', sql.NVarChar(50), password ?? null)
            .input('is_using_google', sql.Bit, is_using_google ?? false)
            .execute('rpiAPSAW_spLoginControlAccess');

        if (result.recordset.length > 0) {
            // Simplify the response
            const spOutput = result.recordset[0]?.json_data || null; // json_data is the alias of a single message return from stored procedure
            console.log(`RES: ${JSON.stringify(result.recordset)}`);
            if (spOutput !== null) {
                res.status(200).json(spOutput);
            } else {
                res.status(200).json(result.recordset);  // result - instance in dart: Map<String, dynamic> | result.recordset - instance in dart: List<dynamic>
            }

        } else {
            res.status(200).json({ message: "Not available at this time." });

        }
    } catch (err) {
        res.status(500).send({ message: err.message });
        await logsErrorExceptions('signIn: ' + err.message); //always double check the method name
    }
}

const logAdminWebAccess = async (req, res) => {
    const { admin_id, username, full_name, comp_email, admin_role, login_status } = req.body;

    try {
        const pool = await poolPromise;
        const request = pool.request();
        const result = await request.input('admin_id', sql.NVarChar(254), admin_id ?? null)
            .input('username', sql.NVarChar(50), username ?? null)
            .input('full_name', sql.NVarChar(50), full_name ?? null)
            .input('comp_email', sql.NVarChar(50), comp_email ?? null)
            .input('admin_role', sql.NVarChar(50), admin_role ?? null)
            .input('login_status', sql.NVarChar(50), login_status ?? null)
            .execute('rpiAPSAW_spLoginControlAccessLogs');

        if (result.recordset.length > 0) {
            // Simplify the response
            const spOutput = result.recordset[0]?.json_data || null; // json_data is the alias of a single message return from stored procedure
            console.log(`RES: ${JSON.stringify(result.recordset)}`);
            if (spOutput !== null) {
                res.status(200).json(spOutput);
            } else {
                res.status(200).json(result.recordset);  // result - instance in dart: Map<String, dynamic> | result.recordset - instance in dart: List<dynamic>
            }

        } else {
            res.status(200).json({ message: "Not available at this time." });

        }
    } catch (err) {
        res.status(500).send({ message: err.message });
        await logsErrorExceptions('logAdminWebAccess: ' + err.message); //always double check the method name
    }
}

const manageDeviceProperties = async (req, res) => {
    const { admin_id, device_platform, device_state, device_model, device_version, function_key } = req.body;

    try {
        const pool = await poolPromiseLogs;
        const request = pool.request();
        const result = await request.input('admin_id', sql.VarChar(50), admin_id ?? null)
            .input('device_platform', sql.VarChar(200), device_platform ?? null)
            .input('device_state', sql.Bit, device_state ?? null)
            .input('device_model', sql.VarChar(200), device_model ?? null)
            .input('device_version', sql.VarChar(200), device_version ?? null)
            .input('function_key', sql.VarChar(100), function_key ?? null)
            .execute('rpiAPSAWL_spManageUserDeviceProperties');

        if (result.recordset.length > 0) {
            // Simplify the response
            const spOutput = result.recordset[0]?.SP_OUTPUT || null; // SP_OUTPUT is the alias of a single message return from stored procedure
            console.log(`RES: ${JSON.stringify(result.recordset)}`);
            if (spOutput !== null) {
                res.status(200).json(spOutput);
            } else {
                res.status(200).json(result.recordset);  // result - instance in dart: Map<String, dynamic> | result.recordset - instance in dart: List<dynamic>
            }

        } else {
            res.status(200).json({ message: "Not available at this time." });
        }
    } catch (err) {
        res.status(500).send({ message: err.message });
        await logsErrorExceptions('manageDeviceProperties: ' + err.message); //always double check the method name
    }
}

/* END OF MICROSOFT SQL SERVER 2008 R2 */

export {
    authenticate,
    fetchData,
    getRandomText,
    addRandomText,
    updateRandomText,
    deleteRandomText,

    signIn,
    logAdminWebAccess,
    manageDeviceProperties,
};