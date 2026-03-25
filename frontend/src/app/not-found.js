import Link from "next/link";

export default function NotFound() {
  return (
    <div className="relative min-h-screen flex items-center justify-center text-white font-mono">

      {/* Content */}
      <div className="flex flex-col items-center text-center px-6">

        {/* 404 Heading */}
        <div className="flex items-baseline gap-3">
          <h1 className="text-7xl font-bold tracking-wide font-mono">404</h1>
          <h2 className="text-4xl font-semibold opacity-80">Not Found</h2>
        </div>

        {/* Message */}
        <p className="mt-4 text-gray-300 text-sm tracking-wide">
          The page you are looking for does not exist or has been moved.
        </p>

        {/* Button */}
        <Link
          href="/"
          className="mt-8 px-5 py-2 rounded-full border border-white/20 hover:border-white/40 hover:bg-white/10 transition-all text-sm"
        >
          Go Back Home
        </Link>

      </div>
    </div>
  );
}