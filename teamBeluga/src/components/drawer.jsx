import { X } from "lucide-react";

const Drawer = ({ isOpen, setIsOpen }) => {
  return (
    <div className="fixed top-0 left-0 h-full w-64 bg-gray-900 text-white shadow-lg p-5 z-50">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-semibold">Menu</h2>
        <button onClick={() => setIsOpen(false)}>
          <X size={24} />
        </button>
      </div>
      <ul className="space-y-3">
        <li>
          <a href="/" className="block p-2 hover:bg-gray-700 rounded">Home</a>
        </li>
        <li>
          <a href="/history" className="block p-2 hover:bg-gray-700 rounded">Scan history</a>
        </li>
      </ul>
    </div>
  );
};

export default Drawer;
