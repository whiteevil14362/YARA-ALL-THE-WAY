import { createContext, useContext, useState } from "react";

// Create Context
const AppContext = createContext();

// Create Provider Component
export function AppProvider({ children }) {
  const [isOpen, setIsOpen] = useState(false);
  const [apiBooster, setApiBooster] = useState(false); // Example of another global state

  return (
    <AppContext.Provider value={{ isOpen, setIsOpen, apiBooster, setApiBooster }}>
      {children}
    </AppContext.Provider>
  );
}

// Custom Hook to Use Context
export function useAppContext() {
  return useContext(AppContext);
}
