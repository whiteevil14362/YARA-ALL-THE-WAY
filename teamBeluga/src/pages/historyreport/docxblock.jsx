import { useRef, useCallback } from "react";
import { ShieldCheck, AlertCircle, Calendar, FileText, HardDrive, ChevronDown } from "lucide-react";
import { motion } from "framer-motion";

const DOCXBlock = ({ item, index, expandedItem, setExpandedItem }) => {
  const detailRef = useRef(null);

  const toggleExpand = useCallback(() => {
    setExpandedItem(expandedItem === index ? null : index);
    setTimeout(() => {
      detailRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 200);
  }, [expandedItem, index, setExpandedItem]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05 }}
      className="bg-gray-800 p-4 rounded-lg border-l-4 border-l-blue-600 cursor-pointer"
      onClick={toggleExpand}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          {item.status === "clean" ? (
            <ShieldCheck className="text-green-400 mr-2" size={20} />
          ) : (
            <AlertCircle className="text-red-400 mr-2" size={20} />
          )}
          <span className="text-white font-medium">{item.status.toUpperCase()}</span>
        </div>
        <div className="flex items-center text-gray-400 text-sm">
          <Calendar size={14} className="mr-1" />
          {new Date(item.timestamp).toLocaleString("en-US", {
            month: "short",
            day: "numeric",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          })}
        </div>
      </div>

      <div className="flex items-start mt-2">
        <FileText size={16} className="text-gray-400 mr-2 mt-1" />
        <div className="flex-1">
          <p className="text-gray-300">{item.filename || "Unknown file"}</p>
          <div className="flex items-center text-gray-400 text-sm ml-2">
            <HardDrive size={14} className="mr-1" />
            <span>{item.formatted_size || "Unknown size"}</span>
          </div>
        </div>
      </div>

      {item.threat_level && (
        <div className="mt-2">
          <div className="w-full bg-gray-700 rounded-full h-2.5">
            <div
              className={`h-2.5 rounded-full ${
                item.threat_level === "high" ? "bg-red-500" : item.threat_level === "medium" ? "bg-yellow-500" : "bg-green-500"
              }`}
              style={{ width: item.threat_level === "high" ? "100%" : item.threat_level === "medium" ? "50%" : "0%" }}
            />
          </div>
          <p className="text-xs text-gray-400 mt-1">Threat Level: {item.threat_level || "low"}</p>
        </div>
      )}

      <div className="flex justify-end mt-2">
        <ChevronDown
          size={20}
          className={`transition-transform duration-300 ${expandedItem === index ? "rotate-180" : "rotate-0"} text-gray-400`}
        />
      </div>

      {expandedItem === index && item.yara_results.details !== "No threats found" && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: "auto", opacity: 1 }}
          transition={{ duration: 0.3 }}
          ref={detailRef}
          className="mt-4 bg-gray-900 p-3 rounded-md text-gray-300"
        >
          <h3 className="text-white font-semibold">📋 File Details:</h3>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li className="text-sm text-gray-400 border-b border-gray-700 pb-2">
              <p className="text-gray-300 font-semibold">File Hash:</p>
              <p className="text-gray-400">{item.file_hash}</p>
            </li>
            <li className="text-sm text-gray-400 border-b border-gray-700 pb-2">
              <p className="text-gray-300 font-semibold">File Type:</p>
              <p className="text-gray-400">{item.yara_results.file_type}</p>
            </li>
            <li className="text-sm text-gray-400 border-b border-gray-700 pb-2">
              <p className="text-gray-300 font-semibold">Matches Count:</p>
              <p className="text-gray-400">{item.yara_results.matches_count}</p>
            </li>
          </ul>
        </motion.div>
      )}
    </motion.div>
  );
};

export default DOCXBlock;