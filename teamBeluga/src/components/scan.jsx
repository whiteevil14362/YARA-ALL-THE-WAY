import { useState } from "react";

const HashScanner = () => {
  const [hash, setHash] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!hash) return;
    setLoading(true);
    setError("");
    setScanResult(null);

    try {
      const response = await fetch(
        `https://www.virustotal.com/api/v3/files/${hash}`,
        {
          headers: {
            "x-apikey": import.meta.env.VITE_VIRUS_TOTAL_API_KEY,
          },
        }
      );

      if (!response.ok) {
        throw new Error("Invalid Hash or API Error");
      }

      const data = await response.json();
      setScanResult(data.data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-[90%] max-w-4xl my-8 mx-auto p-6 space-y-6 bg-slate-950 border border-slate-800 rounded-lg text-slate-100">
      <h2 className="text-3xl font-bold">File Hash Scanner</h2>
      <p className="text-slate-400">
        Analyze file hashes for security threats and metadata.
      </p>

      <div className="flex flex-col sm:flex-row gap-4">
        <input
          type="text"
          value={hash}
          onChange={(e) => setHash(e.target.value)}
          placeholder="Enter File Hash (MD5, SHA1, SHA256)"
          className="flex-1 px-4 py-2 rounded-lg bg-slate-900 text-slate-100 border border-slate-800 focus:ring-2 focus:ring-blue-500 w-full"
        />
        <button
          onClick={handleScan}
          disabled={loading}
          className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition disabled:opacity-50"
        >
          {loading ? "Scanning..." : "Scan"}
        </button>
      </div>

      {error && <Alert type="error" message={error} />}
      {scanResult && <ScanDetails result={scanResult} />}
    </div>
  );
};

const Alert = ({ type, message }) => (
  <div
    className={`p-4 border rounded-lg ${
      type === "error"
        ? "bg-red-950 border-red-800 text-red-100"
        : "bg-green-950 border-green-800 text-green-100"
    }`}
  >
    <span className="font-semibold">
      {type === "error" ? "Error" : "Success"}
    </span>
    <p className="mt-2 break-words">{message}</p>
  </div>
);

const ScanDetails = ({ result }) => {
  const { attributes } = result;
  const totalScanners = Object.values(attributes.last_analysis_stats).reduce(
    (sum, value) => sum + value,
    0
  );

  const isSafe = attributes.last_analysis_stats.malicious === 0;

  return (
    <div className="space-y-6">
      <Alert
        type={isSafe ? "success" : "error"}
        message={
          isSafe
            ? "No security threats detected."
            : `${attributes.last_analysis_stats.malicious} out of ${totalScanners} scanners flagged this file as malicious.`
        }
      />

      <InfoCard
        title="File Details"
        items={[
          { label: "Name", value: attributes.names?.[0] || "Unknown" },
          { label: "Type", value: attributes.type_description || "Unknown" },
          { label: "Size", value: `${attributes.size} bytes` },
          { label: "Format", value: attributes.magic || "Unknown Format" },
        ]}
      />

      <InfoCard
        title="Hash Values"
        items={[
          { label: "MD5", value: attributes.md5 },
          { label: "SHA-1", value: attributes.sha1 },
          { label: "SHA-256", value: attributes.sha256 },
        ]}
      />

      <InfoCard
        title="Scan Results"
        items={[
          { label: "Total Scanners", value: totalScanners },
          {
            label: "Malicious Detections",
            value: attributes.last_analysis_stats.malicious,
          },
          {
            label: "Clean Detections",
            value: totalScanners - attributes.last_analysis_stats.malicious,
          },
        ]}
      />
    </div>
  );
};

const InfoCard = ({ title, items }) => (
  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
    <h3 className="text-lg font-semibold mb-2">{title}</h3>
    <div className="space-y-2">
      {items.map((item, index) => (
        <div
          key={index}
          className="flex flex-col sm:flex-row sm:justify-between text-slate-300 break-words"
        >
          <span className="text-slate-400">{item.label}</span>
          <span className="mt-1 sm:mt-0">{item.value}</span>
        </div>
      ))}
    </div>
  </div>
);

export default HashScanner;
