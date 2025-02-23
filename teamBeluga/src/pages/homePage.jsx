import { motion } from "framer-motion"; 
import UploadFile from "../components/uploadfile";
import Scan from "../components/scan";
import { useState } from "react";
import back from "../assets/back.svg";

const Home = ({ isOpen, setIsOpen }) => {
  const [activePage, setActivePage] = useState("File");
  const [loading, setLoading] = useState(false);
  const pages = ["File", "Scan"];

  return (
<motion.div
  className="flex flex-col w-full h-screen bg-[#13131B] bg-center bg-no-repeat overflow-auto scrollbar-custom py-6"
  style={{
    backgroundImage: `url(${back})`,
    backgroundSize: "50%", // ✅ Adjust size (e.g., 50% of the container)
  }}
  animate={{ x: isOpen ? 200 : 0 }}
  transition={{ duration: 0.3, ease: "easeInOut" }}
>


      {/* Main Content */}
      <div className="w-full h-full flex flex-col items-center justify-start">
        {/* Navigation Buttons */}
        <div className="w-full flex justify-center items-center space-x-8">
          {pages.map((item, index) => {
            const isActive = activePage === item;
            return (
              <div
                key={index}
                className="relative w-40 text-center cursor-pointer"
                onClick={() => setActivePage(item)}
              >
                <motion.h1
                  className={`text-lg font-semibold ${
                    isActive ? "text-blue-500" : "text-blue-300"
                  }`}
                  whileHover={{ scale: 1.1 }}
                  transition={{ type: "spring", stiffness: 200 }}
                >
                  {item}
                </motion.h1>

                {/* Animated underline */}
                <motion.div
                  className="absolute left-0 right-0 h-[3px] bg-cyan-300 mt-1"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: isActive ? 1 : 0 }}
                  transition={{ duration: 0.3, ease: "easeInOut" }}
                />
              </div>
            );
          })}
        </div>

        {/* Page Content with Animation */}
        <motion.div
          key={activePage}
          className="w-full flex justify-center items-center pb-12"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: "easeOut" }}
        >
          {activePage === "File" && (
            <UploadFile loading={loading} setLoading={setLoading} />
          )}
          {activePage === "Upload" && <Url />}
          {activePage === "Scan" && <Scan />}
        </motion.div>
      </div>
    </motion.div>
  );
};

export default Home;
