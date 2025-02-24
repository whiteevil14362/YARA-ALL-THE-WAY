import { Menu } from "lucide-react";
import { motion } from "framer-motion";
import { useAppContext } from "../AppContext";
import logo from "../assets/logo.svg";

function Navbar({ setIsOpen }) {
  const { setApiBooster, apiBooster } = useAppContext();

  return (
    <div className="w-full h-16 flex items-center justify-between px-4 md:px-6 bg-[#13131B] text-white shadow-md">
      {/* Left - Menu Icon */}
      <div onClick={() => setIsOpen(true)} className="flex items-center">
        <Menu size={28} className="cursor-pointer hover:text-gray-400 transition-all" />
      </div>

      {/* Center - Brand Name and Logo */}
      <div className="flex items-center gap-2">
        <img src={logo} alt="Team Beluga Logo" className="h-12 w-auto filter invert" />
        <h1 className="text-xl md:text-2xl font-bold tracking-wide text-white hover:text-gray-300 transition-all hidden sm:block">
          YARA ALL THE WAY
        </h1>
      </div>

      {/* Right - Empty Space (for future use) */}
      <div></div>
    </div>
  );
}

export default Navbar;