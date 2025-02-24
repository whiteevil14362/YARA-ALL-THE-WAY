import { useEffect, useState } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import ScanHistory from "./historyreport/scanhistory";

const HistoryPage = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [threatFilter, setThreatFilter] = useState("All");


  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch(
          `${import.meta.env.VITE_API_URL}/stats?userid=yyoo`
        );
        if (!response.ok) throw new Error("Failed to fetch stats");
        const data = await response.json();
        setStats(data.stats);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  if (loading)
    return <div className="text-white text-center pt-10 h-full bg-[#13131B]">Loading...</div>;
  if (error)
    return (
      <div className="text-red-500 text-center pt-10 w-full h-full bg-[#13131B]">
        Error loading statistics: {error}
      </div>
    );

  const pieData = [
    { name: "Clean Files", value: stats?.clean_files || 0 },
    { name: "Infected Files", value: stats?.infected_files || 0 },
  ];

  const COLORS = ["#22c55e", "#ef4444"];

  return (
    <div className="bg-[#13131B] text-white h-full p-6 overflow-auto scrollbar-custom">
      <h1 className="text-2xl font-bold text-center mb-6">
        Scan Statistics Overview
      </h1>

      {/* Search & Filter */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-4 mb-6">
        <input
          type="text"
          placeholder="Search by filename..."
          className="px-4 py-2 rounded-md bg-gray-800 text-white border border-gray-600 w-full md:w-1/3 focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={searchTerm}
          onChange={(e) => {
            setSearchTerm(e.target.value);
          }}
        />
        <select
          className="px-4 py-2 rounded-md bg-gray-800 text-white border border-gray-600 w-full md:w-1/4 focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={threatFilter}
          onChange={(e) => setThreatFilter(e.target.value)}
        >
          <option value="All">All Threat Levels</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>

      {/* Top Section */}
      <div className="flex flex-col md:flex-row justify-between gap-6">
        {/* Chart on the Left */}
        <div className="w-full md:w-1/2 h-72 bg-gray-800 p-4 rounded-lg shadow-lg">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                fill="#8884d8"
                paddingAngle={5}
                dataKey="value"
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "#1f2937",
                  border: "none",
                  color: "white",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Details on the Right */}
        <div className="w-full md:w-1/2 bg-gray-800 p-4 rounded-lg shadow-lg flex flex-row justify-between items-start">
          <div className="flex flex-col">
            <div>
              Total Scans:{" "}
              <span className="font-semibold">{stats?.total_scans || 0}</span>
            </div>
            <div>
              Clean Files:{" "}
              <span className="text-green-400 font-semibold">
                {stats?.threat_levels?.low || 0}
              </span>
            </div>
            <div>
              Infected Files:{" "}
              <span className="text-red-400 font-semibold">
                {stats?.infected_files || 0}
              </span>
            </div>
            <div>
              High Risk Files:{" "}
              <span className="text-red-500 font-semibold">
                {stats?.threat_levels?.high || 0}
              </span>
            </div>
            <div>
              Medium Risk Files:{" "}
              <span className="text-yellow-400 font-semibold">
                {stats?.threat_levels?.medium || 0}
              </span>
            </div>
          </div>
          <div className="flex flex-col gap-2">
            <div className="flex justify-between gap-14">
              <span className="text-white font-medium">PDF:</span>
              <span className="text-green-400 font-semibold">
                {stats.file_types.pdf}
              </span>
            </div>
            <div className="flex justify-between gap-14">
              <span className="text-white font-medium">DOCX:</span>
              <span className="text-blue-400 font-semibold">
                {stats.file_types.docx}
              </span>
            </div>
            <div className="flex justify-between gap-14">
              <span className="text-white font-medium">EXE:</span>
              <span className="text-red-400 font-semibold">{stats.file_types.exe}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Scan History Section */}
      <div className="mt-10">
        <h2 className="text-xl font-semibold mb-4">Recent Scans</h2>
        <ScanHistory searchTerm={searchTerm} threatFilter={threatFilter} />
      </div>
    </div>
  );
};

export default HistoryPage;
