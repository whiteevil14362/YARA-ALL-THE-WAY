import { Routes, Route } from "react-router-dom";
import { motion } from "framer-motion";
import Home from "./pages/homePage";
import HistoryPage from "./pages/historyPage";
import Navbar from "./components/navbar";
import { useState, useEffect } from "react";
import ScanningPage from "./pages/scanningPage";
import Drawer from "./components/drawer";

function App() {
  const [isOpen, setIsOpen] = useState(false);

  // Function to generate a random token
  const generateRandomToken = () => {
    return Math.random().toString(36).substr(2, 16); // Generates a random 16-character token
  };

  // Check if a token exists in localStorage, if not, generate and save one
  useEffect(() => {
    const existingToken = localStorage.getItem("userToken");
    if (!existingToken) {
      const token = generateRandomToken();
      localStorage.setItem("userToken", token);
    }
  }, []); // Empty dependency array ensures this runs only once when the component mounts

  return (
    <div className="h-screen w-full fixed flex overflow-hidden">
      {/* Animated Drawer */}
      <motion.div
        initial={{ x: "-100%" }}
        animate={{ x: isOpen ? 0 : "-100%" }}
        transition={{ duration: 0.3, ease: "easeInOut" }}
        className="fixed top-0 left-0 h-full w-64 bg-gray-900 text-white shadow-lg p-5 z-50"
      >
        <Drawer isOpen={isOpen} setIsOpen={setIsOpen} />
      </motion.div>

      {/* Animated Navbar + Page Content */}
      <motion.div
        animate={{ x: isOpen ? 200 : 0 }} // Move right when drawer opens
        transition={{ duration: 0.3, ease: "easeInOut" }}
        className="flex flex-col w-full"
      >
        {/* Navbar */}
        <Navbar setIsOpen={setIsOpen} />

        {/* Page Content */}
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/scan" element={<ScanningPage />} />
        </Routes>
      </motion.div>
    </div>
  );
}

export default App;
