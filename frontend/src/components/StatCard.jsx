export default function StatCard({ label, value, highlight = false }) {
  return (
    <div className={`glass-panel rounded-xl p-4 ${highlight ? "border-cyber-400" : ""}`}>
      <p className="panel-title">{label}</p>
      <p className="mt-2 font-display text-3xl font-bold text-cyber-100">{value}</p>
    </div>
  );
}
