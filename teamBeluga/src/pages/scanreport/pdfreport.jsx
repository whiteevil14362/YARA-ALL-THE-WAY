import { useState } from "react";
import { motion } from "framer-motion";
import { FileText, ChevronDown, ChevronUp } from "lucide-react";

const formatFileSize = (bytes) => {
  if (!bytes) return "Unknown size";
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
};

const PDFReport = ({ scanResult }) => {
  const [showDetails, setShowDetails] = useState(false);

  if (!scanResult) return <p className="text-red-500">No scan results available.</p>;

  const { filename, filesize, threat_level, matches_count, yara_details } = scanResult;

  const bgColor =
    threat_level === "high"
      ? "bg-red-700"
      : threat_level === "medium"
      ? "bg-yellow-600"
      : "bg-green-700";

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={`p-6 rounded-lg flex flex-col gap-3 relative shadow-lg ${bgColor}`}
    >
      <div className="flex items-center gap-4">
        <FileText size={28} className="text-gray-100" />
        <div className="w-full overflow-hidden">
          <p className="text-white text-lg font-semibold break-words">{filename || "Unknown"}</p>
          <p className="text-gray-300">Size: {formatFileSize(filesize)}</p>
          <p
            className={`text-lg font-semibold ${
              threat_level === "high"
                ? "text-red-300"
                : threat_level === "medium"
                ? "text-yellow-300"
                : "text-green-300"
            }`}
          >
            Threat Level: {threat_level ? threat_level.toUpperCase() : "Unknown"}
          </p>
          <p className="text-gray-200">Matches Found: {matches_count || 0}</p>
        </div>
      </div>

      <button
        onClick={() => setShowDetails(!showDetails)}
        className="flex items-center gap-2 text-gray-200 font-bold mt-2 cursor-pointer hover:opacity-80"
      >
        For Nerds
        {showDetails ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
      </button>

      <motion.div
        initial={false} // ✅ Prevents initial animation (fixes blinking)
        animate={{ height: showDetails ? "auto" : 0, opacity: showDetails ? 1 : 0.5 }}
        transition={{ duration: 0.3, ease: "easeInOut" }}
        className={`overflow-hidden mt-3 p-3 rounded-lg bg-gray-800/50 space-y-2 ${
          showDetails ? "py-3 px-3" : "py-0 px-3"
        }`}
      >
        {yara_details.length > 0 ? (
          yara_details.map((detail, idx) => (
            <div key={idx} className="bg-gray-900 p-3 rounded-lg">
              <p className="text-gray-200">🔍 {detail.description}</p>
              <p className="text-gray-400">⚖️ Rule: {detail.rule} | Weight: {detail.weight}</p>
            </div>
          ))
        ) : (
          <p className="text-green-300">✅ No threats found.</p>
        )}
      </motion.div>
    </motion.div>
  );
};

export default PDFReport;
