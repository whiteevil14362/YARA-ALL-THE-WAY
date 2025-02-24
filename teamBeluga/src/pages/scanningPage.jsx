import { useLocation, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import axios from "axios";
import { Loader, FileText } from "lucide-react";
import { motion } from "framer-motion";
import PDFReport from "./scanreport/pdfreport";
import DOCXReport from "./scanreport/docxreport";
import EXEReport from "./scanreport/exereport";

const ScanningPage = () => {
  const userid = "yyoo";
  const location = useLocation();
  const navigate = useNavigate();
  const files = location.state?.files
    ? Array.isArray(location.state.files)
      ? location.state.files
      : [location.state.files]
    : [];
  const [loading, setLoading] = useState(true);
  const [scanResults, setScanResults] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    if (files.length === 0) {
      setError("❌ No files found. Please upload again.");
      setLoading(false);
      return;
    }

    const scanFiles = async () => {
      setLoading(true);
      const results = [];

      for (const file of files) {
        const formData = new FormData();
        formData.append("file", file);
        formData.append("userid", userid);

        try {
          // 🔹 Our API Scan
          const response = await axios.post(
            `${import.meta.env.VITE_API_URL}/scan`,
            formData,
            { headers: { "Content-Type": "multipart/form-data" } }
          );
          results.push(response.data.scan_result || {});
        } catch (err) {
          console.error("Our API scan failed for", file.name, err.response?.data || err.message);
          results.push({
            filename: file.name,
            status: "Error",
            details: err.response?.data || err.message,
            threat_level: "high",
            formatted_size: `${(file.size / 1024).toFixed(2)} KB`,
            timestamp: new Date().toISOString(),
          });
        }
      }

      setScanResults(results);
      setLoading(false);
    };

    scanFiles();
  }, [files]);

  return (
    <div className="bg-[#13131B] h-full text-gray-300 flex flex-col items-center p-6 overflow-auto scrollbar-custom">
      <div className="w-full max-w-6xl bg-gray-900 p-6 rounded-lg shadow-xl py-12">
        <h3 className="text-white text-xl font-bold mb-4">🔍 Scanning Results</h3>

        {loading ? (
          <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1 }}>
            <Loader size={50} className="text-blue-400 animate-spin mx-auto" />
          </motion.div>
        ) : error ? (
          <p className="text-red-400 text-center">{error}</p>
        ) : (
          <div className="grid grid-cols-1">
            {/* Our Scan Results */}
            <div>
              {scanResults.map((result, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3 }}
                  className={`p-4 my-4 rounded-lg flex flex-col gap-2 ${
                    result.threat_level === "high"
                      ? "bg-red-700"
                      : result.threat_level === "medium"
                      ? "bg-yellow-600"
                      : "bg-green-700"
                  }`}
                >
                  {result.file_type === "pdf" ? (
                    <PDFReport scanResult={result} />
                  ) : result.file_type === "docx" ? (
                    <DOCXReport scanResult={result} />
                  ) : result.file_type === "exe" ? (
                    <EXEReport scanResult={result} />
                  ) : (
                    <div className="flex items-center gap-3">
                      <FileText size={20} className="text-gray-200" />
                      <div>
                        <p className="text-white font-medium">{result.filename}</p>
                        <p className="text-gray-300">Size: {result.formatted_size}</p>
                        <p className="text-white font-semibold">Threat Level: {result.threat_level.toUpperCase()}</p>
                        <p className="text-gray-200">Matches Found: {result.matches_count || 0}</p>
                        <p className="text-gray-200">Timestamp: {new Date(result.timestamp).toLocaleString()}</p>
                      </div>
                    </div>
                  )}
                </motion.div>
              ))}
            </div>
          </div>
        )}

        <button
          onClick={() => navigate("/")}
          className="mt-6 bg-blue-600 px-4 py-2 rounded-lg text-white hover:bg-blue-500 transition-all w-full"
        >
          🔄 Back to Upload
        </button>
      </div>
    </div>
  );
};

export default ScanningPage;