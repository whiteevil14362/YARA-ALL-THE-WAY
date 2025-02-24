import { motion } from "framer-motion";
import { FileText, ChevronDown, ChevronUp } from "lucide-react";
import { useState } from "react";

const EXEReport = ({ scanResult }) => {
  const [showDetails, setShowDetails] = useState(false);

  if (!scanResult) {
    return <p className="text-gray-300">No scan result available.</p>;
  }

  const {
    filename = "Unknown",
    formatted_size = "N/A",
    filesize = "N/A",
    timestamp = "N/A",
    sha256 = "N/A",
    imphash = "N/A",
    suspicious_strings = [],
    pe_analysis = [],
    yara_matches = [],
    threat_level="low"
  } = scanResult;

  const isDangerous = threat_level === "high";
  const bgColor = isDangerous ? "bg-red-700" : "bg-green-700";

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
          <p className="text-white text-lg font-semibold break-words">{filename}</p>
          <p className="text-gray-300">Size: {formatted_size} ({filesize} bytes)</p>
          <p className="text-gray-300">Timestamp: {new Date(timestamp).toLocaleString()}</p>
          <p
            className={`text-lg font-semibold ${
              isDangerous ? "text-red-300" : "text-green-300"
            }`}
          >
            Threat Level: {threat_level}
          </p>
          <p className="text-gray-200 break-all">SHA-256: {sha256}</p>
          <p className="text-gray-200 break-all">Import Hash: {imphash}</p>
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
        initial={false} // Prevents blinking
        animate={{ height: showDetails ? "auto" : 0, opacity: showDetails ? 1 : 0.5 }}
        transition={{ duration: 0.3, ease: "easeInOut" }}
        className={`overflow-hidden mt-3 p-3 rounded-lg bg-gray-800/50 ${
          showDetails ? "py-3 px-3" : "py-0 px-3"
        }`}
      >
        <div className="text-gray-300">
          <p className="font-bold text-gray-100">Suspicious Strings:</p>
          <p>{suspicious_strings.length > 0 ? suspicious_strings.join(", ") : "None"}</p>

          {pe_analysis.length > 0 && (
            <>
              <p className="font-bold text-gray-100 mt-2">PE Analysis:</p>
              <p>{pe_analysis.join(", ")}</p>
            </>
          )}

          {yara_matches.length > 0 && (
            <>
              <p className="font-bold text-gray-100 mt-2">YARA Matches:</p>
              <p>{yara_matches.join(", ")}</p>
            </>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
};

export default EXEReport;
