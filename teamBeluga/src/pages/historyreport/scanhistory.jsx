import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import axios from "axios";
import { useInView } from "react-intersection-observer";
import { Loader } from "lucide-react";
import { motion } from "framer-motion";
import PDFBlock from "./pdfblock";
import EXEBlock from "./exeblock";
import DOCXBlock from "./docxblock";

const ScanHistory = ({ userid , searchTerm, threatFilter }) => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [expandedItem, setExpandedItem] = useState(null);

  const { ref, inView } = useInView();
  const controller = useRef(new AbortController());

  const fetchHistory = useCallback(async () => {
    if (!userid || loading || !hasMore) return;

    setLoading(true);
    controller.current.abort();
    controller.current = new AbortController();

    try {
      const response = await axios.get(`${import.meta.env.VITE_API_URL}/history`, {
        params: { userid, page, limit: 5 },
        signal: controller.current.signal,
      });

      const newHistory = response.data.history || [];

      setHistory((prev) => [...prev, ...newHistory]);
      setHasMore(newHistory.length > 0);
      setPage((prev) => prev + 1);
    } catch (err) {
      if (axios.isCancel(err)) return;
      console.error("Error fetching history:", err);
    }
    setLoading(false);
  }, [userid, page, loading, hasMore]);

  useEffect(() => {
    fetchHistory();
  }, []);

  useEffect(() => {
    if (inView) fetchHistory();
  }, [inView]);

  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      const filename = item.filename?.toLowerCase() || "";
      const threatLevel = item.threat_level?.toLowerCase() || "";
      const search = searchTerm?.trim().toLowerCase() || "";
      const threatFilterNormalized = threatFilter?.toLowerCase() || "all";

      const matchesSearch = !search || filename.includes(search);
      const matchesThreat = threatFilterNormalized === "all" || threatLevel.includes(threatFilterNormalized);

      return matchesSearch && matchesThreat;
    });
  }, [history, searchTerm, threatFilter]);

  const renderBlock = (item, index) => {
    switch (item.file_type?.toLowerCase()) {
      case "pdf":
        return <PDFBlock key={item.id || index} item={item} index={index} expandedItem={expandedItem} setExpandedItem={setExpandedItem} />;
      case "exe":
        return <EXEBlock key={item.id || index} item={item} index={index} expandedItem={expandedItem} setExpandedItem={setExpandedItem} />;
      case "docx":
        return <DOCXBlock key={item.id || index} item={item} index={index} expandedItem={expandedItem} setExpandedItem={setExpandedItem} />;
      default:
        return null; // Handle unknown file types or fallback
    }
  };

  return (
    <div className="w-full">
      {filteredHistory.length === 0 && !loading ? (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-gray-400 text-center py-8">
          <p>No scan history available.</p>
        </motion.div>
      ) : (
        <div className="space-y-4">
          {filteredHistory.map((item, index) => renderBlock(item, index))}
        </div>
      )}

      {loading && (
        <div className="flex justify-center py-4">
          <Loader size={24} className="text-blue-400 animate-spin" />
        </div>
      )}
      <div ref={ref} className="h-10"></div>
    </div>
  );
};

export default ScanHistory;