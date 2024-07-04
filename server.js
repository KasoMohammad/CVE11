require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const fetch = require('cross-fetch');
const cors = require('cors');
const moment = require('moment');
const CVE = require('./models/cve');
const CvssCVE = require('./models/cvssCve'); // Import the CvssCVE model
const BackupCVE = require('./models/backupCve');
const Asset = require('./models/asset');

const app = express();

mongoose.connect('mongodb://localhost:27017/cves', { useNewUrlParser: true, useUnifiedTopology: true });

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Verbindungsfehler:'));
db.once('open', function () {
    console.log('Mit MongoDB verbunden');
});

app.use(cors());
app.use(express.json());

const apiKey = process.env.API_KEY;
const maxDaysRange = 120;
const batchSize = Number.MAX_SAFE_INTEGER;
const maxRetries = 10;
const retryDelay = 30000;

// Definition der fetchAllCVEs-Funktion
async function fetchAllCVEs() {
    const latestCVE = await CVE.findOne().sort({ lastModified: -1 });
    let startDate = latestCVE ? moment(latestCVE.lastModified) : moment('2024-01-01');
    const endDate = moment();
    let allCVERecords = [];
    let totalCVEsFetched = 0;

    while (startDate.isBefore(endDate)) {
        const nextEndDate = moment.min(startDate.clone().add(maxDaysRange, 'days'), endDate);
        let startIndex = 0;
        let totalResults = 0;

        do {
            try {
                const { cveRecords, totalResults: fetchedTotalResults } = await fetchCVEs(startDate.toISOString(), nextEndDate.toISOString(), startIndex);
                allCVERecords = allCVERecords.concat(cveRecords);
                totalCVEsFetched += cveRecords.length;
                startIndex += 100;  // Update the index for pagination
                totalResults = fetchedTotalResults;
                console.log(`[OLD API] Fetched ${cveRecords.length} CVEs from ${startDate.toISOString()} to ${nextEndDate.toISOString()}`);
            } catch (error) {
                console.error(`[OLD API] Fehler beim Abrufen der CVEs für den Zeitraum ${startDate.toISOString()} bis ${nextEndDate.toISOString()}:`, error);
                break;
            }
        } while (startIndex < totalResults);

        startDate = nextEndDate.add(1, 'days');
        await new Promise(resolve => setTimeout(resolve, 6000)); // Warte 6 Sekunden zwischen den Anfragen
    }

    console.log(`[OLD API] Total CVEs fetched: ${totalCVEsFetched}`);

    for (let i = 0; i < allCVERecords.length; i += batchSize) {
        const batch = allCVERecords.slice(i, i + batchSize);
        const bulkOps = batch.map((record) => ({
            updateOne: {
                filter: { id: record.id },
                update: record,
                upsert: true,
            },
        }));
        await CVE.bulkWrite(bulkOps);
        console.log(`[OLD API] Saved batch of ${batch.length} CVEs to the database.`);
    }

    console.log(`[OLD API] Insgesamt ${allCVERecords.length} CVEs abgerufen und gespeichert.`);
    console.log('[OLD API] Fetching complete.');
}

// Der Rest deines Codes bleibt unverändert

async function fetchCVEs(startDate, endDate, startIndex = 0, retries = maxRetries) {
    const apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&startIndex=${startIndex}&pubStartDate=${encodeURIComponent(startDate)}&pubEndDate=${encodeURIComponent(endDate)}`;
    console.log('[OLD API] Fetching CVEs with parameters:', apiUrl);

    try {
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'apiKey': apiKey,
            },
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`[OLD API] HTTP-Fehler! Status: ${response.status}, Message: ${errorText}`);
        }

        const data = await response.json();

        if (!data.vulnerabilities) {
            throw new Error('[OLD API] Ungültiges Datenformat von der API erhalten');
        }

        const cveRecords = data.vulnerabilities.map((item) => ({
            id: item.cve.id,
            sourceIdentifier: item.cve.sourceIdentifier,
            published: parseDate(item.cve.published),
            lastModified: parseDate(item.cve.lastModified),
            vulnStatus: item.cve.vulnStatus,
            descriptions: item.cve.descriptions,
            metrics: item.cve.metrics,
            weaknesses: item.cve.weaknesses,
            configurations: item.cve.configurations,
            references: item.cve.references.map((ref) => ref.url),
        }));

        console.log(`[OLD API] Fetched ${cveRecords.length} CVEs from ${startDate} to ${endDate}`);

        return {
            cveRecords,
            totalResults: data.totalResults,
        };
    } catch (error) {
        console.error('[OLD API] Fehler beim Abrufen der CVEs:', error.message);
        if (retries > 0) {
            const delay = retryDelay + Math.floor(Math.random() * 10000);  // Zufällige Verzögerung zwischen 30-40 Sekunden
            console.log(`[OLD API] Erneuter Versuch in ${delay / 1000} Sekunden... (${retries} verbleibende Versuche)`);
            await new Promise(resolve => setTimeout(resolve, delay));
            return fetchCVEs(startDate, endDate, startIndex, retries - 1);
        } else {
            throw error;
        }
    }
}

async function fetchCvssCVEs(startIndex = 0, retries = maxRetries) {
    const apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Metrics=AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L&resultsPerPage=100&startIndex=${startIndex}`;
    console.log('[CVSS API] Fetching CVEs from CVSS API with parameters:', apiUrl);

    try {
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'apiKey': apiKey,
            },
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`[CVSS API] HTTP-Fehler! Status: ${response.status}, Message: ${errorText}`);
        }

        const data = await response.json();

        if (!data.vulnerabilities) {
            throw new Error('[CVSS API] Ungültiges Datenformat von der API erhalten');
        }

        const cveRecords = data.vulnerabilities.map((item) => ({
            id: item.cve.id,
            sourceIdentifier: item.cve.sourceIdentifier,
            published: parseDate(item.cve.published),
            lastModified: parseDate(item.cve.lastModified),
            vulnStatus: item.cve.vulnStatus,
            descriptions: item.cve.descriptions,
            metrics: item.cve.metrics,
            weaknesses: item.cve.weaknesses,
            configurations: item.cve.configurations,
            references: item.cve.references.map((ref) => ref.url),
        }));

        console.log(`[CVSS API] Fetched ${cveRecords.length} new CVEs`);

        return {
            cveRecords,
            totalResults: data.totalResults,
        };
    } catch (error) {
        console.error('[CVSS API] Fehler beim Abrufen der neuen CVEs:', error.message);
        if (retries > 0) {
            const delay = retryDelay + Math.floor(Math.random() * 10000);  // Zufällige Verzögerung zwischen 30-40 Sekunden
            console.log(`[CVSS API] Erneuter Versuch in ${delay / 1000} Sekunden... (${retries} verbleibende Versuche)`);
            await new Promise(resolve => setTimeout(resolve, delay));
            return fetchCvssCVEs(startIndex, retries - 1);
        } else {
            throw error;
        }
    }
}

async function fetchAllCvssCVEs() {
    let startIndex = 0;
    let allCVERecords = [];
    let totalCVEsFetched = 0;

    console.log('[CVSS API] Performing initial fetch to determine total number of CVEs');

    // Initialer API-Aufruf, um die Gesamtanzahl der CVEs zu ermitteln
    const initialFetch = await fetchCvssCVEs(startIndex);
    const totalResults = initialFetch.totalResults;
    allCVERecords = initialFetch.cveRecords;
    totalCVEsFetched = initialFetch.cveRecords.length;
    startIndex += 100;

    console.log(`[CVSS API] Total number of CVEs to fetch: ${totalResults}`);
    console.log(`[CVSS API] Fetched initial ${initialFetch.cveRecords.length} CVEs`);

    // Wiederhole den Abrufprozess, bis alle CVEs abgerufen sind
    while (totalCVEsFetched < totalResults) {
        try {
            const { cveRecords } = await fetchCvssCVEs(startIndex);
            allCVERecords = allCVERecords.concat(cveRecords);
            totalCVEsFetched += cveRecords.length;
            startIndex += 100; // Update the index for pagination
            console.log(`[CVSS API] Fetched ${cveRecords.length} new CVEs, total fetched: ${totalCVEsFetched}`);
        } catch (error) {
            console.error(`[CVSS API] Fehler beim Abrufen der neuen CVEs:`, error);
            break;
        }
    }

    console.log(`[CVSS API] Total new CVEs fetched: ${totalCVEsFetched}`);

    // Speichern der CVEs in der Datenbank in Batches
    for (let i = 0; i < allCVERecords.length; i += batchSize) {
        const batch = allCVERecords.slice(i, i + batchSize);
        const bulkOps = batch.map((record) => ({
            updateOne: {
                filter: { id: record.id },
                update: record,
                upsert: true,
            },
        }));
        await CvssCVE.bulkWrite(bulkOps);
        console.log(`[CVSS API] Saved batch of ${batch.length} new CVEs to the database.`);
    }

    console.log(`[CVSS API] Insgesamt ${allCVERecords.length} neue CVEs abgerufen und gespeichert.`);
    console.log('[CVSS API] Fetching complete.');
}

// Red Hat API zum Abrufen von CVEs als Backup
async function fetchBackupCVEs(startDate, retries = maxRetries) {
    const apiUrl = `https://access.redhat.com/labs/securitydataapi/cve.json?after=${startDate}`;
    console.log('[Red Hat Backup API] Fetching CVEs with parameters:', apiUrl);

    try {
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`[Red Hat Backup API] HTTP-Fehler! Status: ${response.status}, Message: ${errorText}`);
        }

        const data = await response.json();

        if (!Array.isArray(data)) {
            throw new Error('[Red Hat Backup API] Ungültiges Datenformat von der API erhalten');
        }

        const cveRecords = data.map((item) => ({
            id: item.CVE,
            sourceIdentifier: item.source,
            published: parseDate(item.public_date),
            lastModified: parseDate(item.modified_date),
            vulnStatus: item.status,
            descriptions: item.details ? [{ lang: 'en', value: item.details }] : [],
            metrics: item.cvss3 ? { cvssV3: item.cvss3 } : {},
            weaknesses: [],
            configurations: [],
            references: item.reference ? [item.reference] : [],
            severity: item.threat_severity,
            public_date: parseDate(item.public_date),
            advisories: item.advisories || [],
            bugzilla: item.bugzilla,
            bugzilla_description: item.bugzilla_description,
            cvss3_score: item.cvss3_score,
            cvss3_scoring_vector: item.cvss3_scoring_vector,
            cvss_score: item.cvss_score,
            cvss_scoring_vector: item.cvss_scoring_vector,
            package_state: item.package_state || [],
            resource_url: item.resource_url
        }));

        console.log(`[Red Hat Backup API] Fetched ${cveRecords.length} CVEs`);

        return {
            cveRecords,
            totalResults: cveRecords.length,
        };
    } catch (error) {
        console.error('[Red Hat Backup API] Fehler beim Abrufen der CVEs:', error.message);
        if (retries > 0) {
            const delay = retryDelay + Math.floor(Math.random() * 10000);  // Zufällige Verzögerung zwischen 30-40 Sekunden
            console.log(`[Red Hat Backup API] Erneuter Versuch in ${delay / 1000} Sekunden... (${retries} verbleibende Versuche)`);
            await new Promise(resolve => setTimeout(resolve, delay));
            return fetchBackupCVEs(startDate, retries - 1);
        } else {
            throw error;
        }
    }
}

async function fetchAllBackupCVEs() {
    let startDate = '2024-01-01';
    let allCVERecords = [];
    let totalCVEsFetched = 0;

    console.log('[Red Hat Backup API] Performing fetch of CVEs');

    while (true) {
        try {
            const { cveRecords } = await fetchBackupCVEs(startDate);
            allCVERecords = allCVERecords.concat(cveRecords);
            totalCVEsFetched += cveRecords.length;
            if (cveRecords.length < 1000) break; // Exit if less than 1000 CVEs were fetched
            startDate = moment(cveRecords[cveRecords.length - 1].published).add(1, 'days').format('YYYY-MM-DD'); // Update the date for the next fetch
            
        } catch (error) {
            console.error(`[Red Hat Backup API] Fehler beim Abrufen der CVEs:`, error);
            break;
        }
    }

    console.log(`[Red Hat Backup API] Total CVEs fetched: ${totalCVEsFetched}`);

    for (let i = 0; i < allCVERecords.length; i += batchSize) {
        const batch = allCVERecords.slice(i, i + batchSize);
        const bulkOps = batch.map((record) => ({
            updateOne: {
                filter: { id: record.id },
                update: record,
                upsert: true,
            },
        }));
        await BackupCVE.bulkWrite(bulkOps);
        console.log(`[Red Hat Backup API] Saved batch of ${batch.length} CVEs to the database.`);
    }

    console.log(`[Red Hat Backup API] Insgesamt ${allCVERecords.length} CVEs abgerufen und gespeichert.`);
    console.log('[Red Hat Backup API] Fetching complete.');
}


async function fetchAllBackupCVEs() {
    let startDate = '2024-01-01';
    let allCVERecords = [];
    let totalCVEsFetched = 0;

    console.log('[Red Hat Backup API] Performing fetch of CVEs');

    while (true) {
        try {
            const { cveRecords } = await fetchBackupCVEs(startDate);
            allCVERecords = allCVERecords.concat(cveRecords);
            totalCVEsFetched += cveRecords.length;
            if (cveRecords.length < 1000) break; // Exit if less than 1000 CVEs were fetched
            startDate = moment(cveRecords[cveRecords.length - 1].published).add(1, 'days').format('YYYY-MM-DD'); // Update the date for the next fetch
            
        } catch (error) {
            console.error(`[Red Hat Backup API] Fehler beim Abrufen der CVEs:`, error);
            break;
        }
    }

    console.log(`[Red Hat Backup API] Total CVEs fetched: ${totalCVEsFetched}`);

    for (let i = 0; i < allCVERecords.length; i += batchSize) {
        const batch = allCVERecords.slice(i, i + batchSize);
        const bulkOps = batch.map((record) => ({
            updateOne: {
                filter: { id: record.id },
                update: record,
                upsert: true,
            },
        }));
        await BackupCVE.bulkWrite(bulkOps);
        console.log(`[Red Hat Backup API] Saved batch of ${batch.length} CVEs to the database.`);
    }

    console.log(`[Red Hat Backup API] Insgesamt ${allCVERecords.length} CVEs abgerufen und gespeichert.`);
    console.log('[Red Hat Backup API] Fetching complete.');
}

function parseDate(dateString) {
    const parsedDate = moment(dateString);
    return parsedDate.isValid() ? parsedDate.toDate() : null;
}

app.post('/api/assets', async (req, res) => {
    try {
        const { text, date, name } = req.body;
        const newAsset = new Asset({ text, date, name });
        await newAsset.save();
        res.status(201).json({ message: 'Asset saved successfully' });
    } catch (error) {
        console.error('Fehler beim Speichern des Assets:', error);
        res.status(500).json({ error: 'Fehler beim Speichern des Assets' });
    }
});

app.get('/api/assets', async (req, res) => {
    try {
        const assets = await Asset.find().populate('cves');
        res.json(assets);
    } catch (error) {
        console.error('Fehler beim Abrufen der Assets:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Assets' });
    }
});

app.put('/api/assets/:id', async (req, res) => {
    try {
        const assetId = req.params.id;
        const { text, date, name } = req.body;
        await Asset.findByIdAndUpdate(assetId, { text, date, name });
        res.status(200).json({ message: 'Asset updated successfully' });
    } catch (error) {
        console.error('Fehler beim Aktualisieren des Assets:', error);
        res.status(500).json({ error: 'Fehler beim Aktualisieren des Assets' });
    }
});

app.delete('/api/assets/:id', async (req, res) => {
    try {
        const assetId = req.params.id;
        await Asset.findByIdAndDelete(assetId);
        res.status(200).json({ message: 'Asset deleted successfully' });
    } catch (error) {
        console.error('Fehler beim Löschen des Assets:', error);
        res.status(500).json({ error: 'Fehler beim Löschen des Assets' });
    }
});

app.get('/api/cves', async function (req, res) {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const cves = await CVE.find().sort({ lastModified: -1 }).skip(skip).limit(limit);
        const total = await CVE.countDocuments();

        res.json({
            cves,
            total,
            page,
            pages: Math.ceil(total / limit),
        });
    } catch (error) {
        console.error('Fehler beim Abrufen der CVEs aus der Datenbank:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der CVEs' });
    }
});

app.get('/api/search', async function (req, res) {
    try {
        const searchQuery = req.query.q;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const searchRegex = new RegExp(searchQuery, 'i');
        const isDate = !isNaN(Date.parse(searchQuery));

        let nvdCves = [];
        let cvssCves = [];
        let backupCves = [];
        let total = 0;

        if (isDate) {
            const date = moment(searchQuery).startOf('day').toDate();
            const nextDate = moment(searchQuery).endOf('day').toDate();

            nvdCves = await CVE.find({
                $or: [
                    { published: { $gte: date, $lte: nextDate } },
                    { lastModified: { $gte: date, $lte: nextDate } }
                ]
            }).sort({ lastModified: -1 }).skip(skip).limit(limit);

            cvssCves = await CvssCVE.find({
                $or: [
                    { published: { $gte: date, $lte: nextDate } },
                    { lastModified: { $gte: date, $lte: nextDate } }
                ]
            }).sort({ lastModified: -1 }).skip(skip).limit(limit);

            backupCves = await BackupCVE.find({
                $or: [
                    { public_date: { $gte: date, $lte: nextDate } },
                    { lastModified: { $gte: date, $lte: nextDate } }
                ]
            }).sort({ lastModified: -1 }).skip(skip).limit(limit);
        } else {
            nvdCves = await CVE.find({
                $or: [
                    { id: { $regex: searchRegex } },
                    { 'descriptions.value': { $regex: searchRegex } },
                    { 'metrics.cvssMetricV2.baseSeverity': { $regex: searchRegex } },
                    { 'metrics.cvssMetricV3.baseSeverity': { $regex: searchRegex } }
                ]
            }).sort({ lastModified: -1 }).skip(skip).limit(limit);

            cvssCves = await CvssCVE.find({
                $or: [
                    { id: { $regex: searchRegex } },
                    { 'descriptions.value': { $regex: searchRegex } },
                    { 'metrics.cvssMetricV2.baseSeverity': { $regex: searchRegex } },
                    { 'metrics.cvssMetricV3.baseSeverity': { $regex: searchRegex } }
                ]
            }).sort({ lastModified: -1 }).skip(skip).limit(limit);

            backupCves = await BackupCVE.find({
                $or: [
                    { id: { $regex: searchRegex } },
                    { 'descriptions.value': { $regex: searchRegex } },
                    { severity: { $regex: searchRegex } }
                ]
            }).sort({ lastModified: -1 }).skip(skip).limit(limit);
        }

        total = nvdCves.length + cvssCves.length + backupCves.length;

        const allCves = [
            ...nvdCves.map(cve => ({ ...cve._doc, source: 'NVD API' })),
            ...cvssCves.map(cve => ({ ...cve._doc, source: 'CVSS API' })),
            ...backupCves.map(cve => ({ ...cve._doc, source: 'Red Hat Backup API' }))
        ];

        res.json({
            cves: allCves,
            total,
            page,
            pages: Math.ceil(total / limit),
        });
    } catch (error) {
        console.error('Fehler beim Suchen der CVEs:', error);
        res.status(500).json({ error: 'Fehler beim Suchen der CVEs' });
    }
});




app.get('/api/cvss-cves', async function (req, res) {
    try {
        const cves = await CvssCVE.find().sort({ lastModified: -1 });
        res.json(cves);
    } catch (error) {
        console.error('Fehler beim Abrufen der neuen CVEs aus der Datenbank:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der neuen CVEs' });
    }
});

app.get('/api/backup-cves', async function (req, res) {
    try {
        const cves = await BackupCVE.find().sort({ lastModified: -1 });
        res.json(cves);
    } catch (error) {
        console.error('Fehler beim Abrufen der CVEs aus der Backup-API:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der CVEs' });
    }
});

app.get('/api/backup-cves/:id', async function (req, res) {
    const cveId = req.params.id;
    const apiUrl = `https://access.redhat.com/hydra/rest/securitydata/cve/${cveId}.json`;

    try {
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Fehler beim Abrufen der CVE-Daten von Red Hat API: ${errorText}`);
        }

        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error(`Fehler beim Abrufen der CVE-Daten von der Red Hat API: ${error.message}`);
        res.status(500).json({ error: 'Fehler beim Abrufen der CVE-Daten' });
    }
});

app.get('/api/assets/:id/cves', async (req, res) => {
    try {
        const assetId = req.params.id;
        const asset = await Asset.findById(assetId);
        if (!asset) {
            return res.status(404).json({ error: 'Asset not found' });
        }

        const cves = await CVE.find({
            'descriptions.value': { $regex: asset.text, $options: 'i' }
        }).lean();

        const cvssCves = await CvssCVE.find({
            'descriptions.value': { $regex: asset.text, $options: 'i' }
        }).lean();

        const backupCves = await BackupCVE.find({
            'descriptions.value': { $regex: asset.text, $options: 'i' }
        }).lean();

        const allCves = [...cves, ...cvssCves, ...backupCves];

        res.json(allCves);
    } catch (error) {
        console.error('Fehler beim Abrufen der betroffenen CVEs:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der betroffenen CVEs' });
    }
});

// Rufe die neuen und alten CVEs ab und speichere sie
fetchAllCvssCVEs();
fetchAllCVEs();
fetchAllBackupCVEs(); // Hinzugefügt für die Backup API

const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
    console.log(`Server läuft auf Port ${PORT}`);
    console.log('Der Server ist jetzt gestartet und die CVEs werden abgerufen.');
});
