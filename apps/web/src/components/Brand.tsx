import { Link } from "react-router-dom";

export function Brand({ compact = false }: { compact?: boolean }) {
  return <Link className="brand" to="/" aria-label="Cascadia home">
    <span className="brand-mark" aria-hidden="true"><i /><i /><i /></span>
    <span className="brand-copy"><b>CASCADIA</b>{!compact && <small>Resilience intelligence</small>}</span>
  </Link>;
}
