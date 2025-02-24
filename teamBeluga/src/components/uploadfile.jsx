import { useState, useRef, useCallback } from "react";
import { Upload, AlertCircle, ShieldCheck, XCircle, Loader, FileText } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import axios from "axios";
import { useDropzone } from "react-dropzone";
import { useNavigate } from "react-router-dom";

const MAX_TOTAL_SIZE_MB = 20;

const UploadFile = ({ loading, setLoading }) => {
  const navigate = useNavigate();
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [error, setError] = useState("");
  const inputRef = useRef(null);

  const getTotalSize = (files) => {
    return files.reduce((total, file) => total + file.size, 0) / (1024 * 1024);
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
    else return (bytes / 1048576).toFixed(2) + ' MB';
  };

  const validateAndAddFiles = (newFiles) => {
    const validFiles = [...uploadedFiles];
    let totalSize = getTotalSize(uploadedFiles);
    let errors = [];

    for (const file of newFiles) {
      const newTotalSize = totalSize + (file.size / (1024 * 1024));
      
      if (newTotalSize > MAX_TOTAL_SIZE_MB) {
        errors.push(`❌ Adding ${file.name} would exceed the ${MAX_TOTAL_SIZE_MB}MB total limit`);
        continue;
      }

      validFiles.push(file);
      totalSize = newTotalSize;
    }

    setUploadedFiles(validFiles);
    setError(errors.length > 0 ? errors[0] : "");
  };

  const handleFileSelect = (event) => {
    validateAndAddFiles(Array.from(event.target.files));
  };

  const handleDrop = useCallback((acceptedFiles) => {
    validateAndAddFiles(acceptedFiles);
  }, [uploadedFiles]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: handleDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
      'application/x-msdownload': ['.exe']
    },
    multiple: true,
  });

  const removeFile = (index) => {
    setUploadedFiles(files => files.filter((_, i) => i !== index));
    setError("");
  };

  const handleScanFiles = () => {
    if (uploadedFiles.length === 0) return;
    navigate("/scan", { state: { files: uploadedFiles } });
  };

  const handleManualUpload = () => {
    inputRef.current?.click();
  };

  return (
    <div className="w-full mt-12 flex flex-col items-center justify-center ">
      <motion.div
        {...getRootProps()}
        className={`w-1/2 h-40 p-3 text-center border-2 border-dashed rounded-xl flex flex-col items-center justify-center transition-all ${
          isDragActive ? "border-blue-500 bg-blue-100" : "border-gray-400 bg-gray-800"
        }`}
        whileHover={{ scale: 1.02 }}
      >
        <input {...getInputProps()} ref={inputRef} />
        <motion.div
          className="text-gray-300 flex flex-col items-center gap-2"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
        >
          <Upload size={24} />
          <p>{isDragActive 
            ? "Drop the files here..." 
            : "Drag & drop files (.exe, .pdf, .docx) here"}
          </p>
          <p className="text-sm text-gray-400">
            Total size limit: {MAX_TOTAL_SIZE_MB}MB
          </p>
        </motion.div>
      </motion.div>

      <motion.button
        onClick={handleManualUpload}
        className="mt-4 bg-gray-700 hover:bg-gray-600 text-white px-6 py-2 rounded-lg flex items-center gap-2 transition-all"
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
      >
        <Upload size={18} />
        Upload Files
      </motion.button>

      <AnimatePresence>
        {error && (
          <motion.div
            className="mt-2 text-red-400 flex items-center gap-2"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
          >
            <AlertCircle size={18} /> {error}
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {uploadedFiles.length > 0 && (
          <motion.div
            className="w-1/2 mt-4 flex flex-col gap-2"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.3 }}
          >
            <div className="bg-gray-900 p-3 rounded-t-lg">
              <p className="text-gray-300">
                Total Size: {formatFileSize(getTotalSize(uploadedFiles) * 1024 * 1024)}
                {" "}/ {MAX_TOTAL_SIZE_MB}MB
              </p>
            </div>
            {uploadedFiles.map((file, index) => (
              <motion.div
                key={`${file.name}-${index}`}
                className="bg-gray-900 p-4 rounded-lg text-gray-300 text-sm flex justify-between items-center"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.3 }}
              >
                <div className="flex items-center gap-2">
                  <FileText size={18} />
                  <div>
                    <p className="text-white font-medium">{file.name}</p>
                    <p className="text-gray-400">{formatFileSize(file.size)}</p>
                  </div>
                </div>
                <motion.button
                  onClick={() => removeFile(index)}
                  className="text-red-500 hover:text-red-400 transition-all"
                  whileTap={{ scale: 0.9 }}
                >
                  <XCircle size={22} />
                </motion.button>
              </motion.div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {uploadedFiles.length > 0 && (
          <motion.button
            onClick={handleScanFiles}
            className="bg-blue-600 w-1/2 mt-4 flex items-center justify-center text-white px-4 py-2 rounded-lg gap-2 hover:bg-blue-500 transition-all"
            whileTap={{ scale: 0.95 }}
            disabled={loading}
          >
            {loading ? (
              <motion.span
                animate={{ rotate: 360 }}
                transition={{ repeat: Infinity, duration: 1, ease: "linear" }}
              >
                <Loader size={20} className="animate-spin" />
              </motion.span>
            ) : (
              <>
                Scan {uploadedFiles.length} {uploadedFiles.length === 1 ? 'File' : 'Files'} <ShieldCheck size={20} />
              </>
            )}
          </motion.button>
        )}
      </AnimatePresence>
    </div>
  );
};

export default UploadFile;