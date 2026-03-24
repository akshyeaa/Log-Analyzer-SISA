"use client";
import { useState, useRef } from "react";

export default function Home() {
  const [files, setFiles] = useState([]);
  const [results, setResults] = useState([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [currentFinding, setCurrentFinding] = useState(0);

  const inputRef = useRef(null);

  const handleUpload = async () => {
    if (files.length === 0) {
      alert("Please upload files first");
      return;
    }

    const formData = new FormData();
    files.forEach((f) => formData.append("files", f));

    const res = await fetch("http://localhost:8000/analyze", {
      method: "POST",
      body: formData,
    });

    const data = await res.json();
    setResults(data.results);
  };

  const selected = results[selectedIndex];

  // 🔥 CONSISTENT FULL HIGHLIGHT
  const renderLines = (text, findings) => {
    const lines = text.split("\n");

    return lines.map((line, i) => {
      const lineFindings = findings.filter((f) => f.line === i + 1);

      let highlightedLine = line;

      lineFindings.forEach((f) => {
        const color =
          f.risk === "critical"
            ? "bg-red-600 text-white"
            : f.risk === "high"
            ? "bg-orange-400 text-black"
            : "bg-yellow-300 text-black";

        // 🔥 highlight FULL PATTERN (not partial)
        const escaped = f.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const regex = new RegExp(escaped, "g");

        highlightedLine = highlightedLine.replace(
          regex,
          `<span class="${color} px-1 rounded">${f.value}</span>`
        );
      });

      let bg = "";
      if (lineFindings.some((f) => f.risk === "critical")) bg = "bg-red-500/20";
      else if (lineFindings.some((f) => f.risk === "high")) bg = "bg-orange-400/20";
      else if (lineFindings.length > 0) bg = "bg-yellow-300/20";

      return (
        <div key={i} id={`line-${i}`} className={`flex px-2 py-1 ${bg}`}>
          <span className="w-10 text-gray-500 text-right mr-3">{i + 1}</span>
          <span
            className="flex-1 whitespace-pre-wrap"
            dangerouslySetInnerHTML={{ __html: highlightedLine }}
          />
        </div>
      );
    });
  };

  // 🔥 REMOVE FILE FROM PREVIEW
  const removeFile = (index) => {
    const newFiles = [...files];
    newFiles.splice(index, 1);
    setFiles(newFiles);
  };

  // 🔥 REMOVE FILE FROM RESULTS (SIDEBAR)
  const removeResult = (index) => {
    const newResults = [...results];
    newResults.splice(index, 1);
    setResults(newResults);
    setSelectedIndex(0);
  };

  // 🔥 NAVIGATION
  const nextFinding = () => {
    if (!selected) return;

    const next = (currentFinding + 1) % selected.findings.length;
    setCurrentFinding(next);

    const line = selected.findings[next].line - 1;
    document.getElementById(`line-${line}`)?.scrollIntoView({
      behavior: "smooth",
      block: "center",
    });
  };

  const prevFinding = () => {
    if (!selected) return;

    const prev =
      (currentFinding - 1 + selected.findings.length) %
      selected.findings.length;

    setCurrentFinding(prev);

    const line = selected.findings[prev].line - 1;
    document.getElementById(`line-${line}`)?.scrollIntoView({
      behavior: "smooth",
      block: "center",
    });
  };

  return (
    <div className="min-h-screen flex text-white">

      {/* Sidebar */}
      {sidebarOpen && (
        <div className="w-72 p-4 bg-white/5 backdrop-blur border-r border-white/10">

          <h2 className="text-center font-bold mb-4 mt-5">FILES</h2>

          <div className="space-y-3">
            {results.map((f, i) => {

              const hasCritical = f.findings.some(x => x.risk === "critical");
              const hasHigh = f.findings.some(x => x.risk === "high");
              const hasLow = f.findings.some(x => x.risk === "low");

              let hoverColor = "hover:border-green-400";
              if (hasCritical) hoverColor = "hover:border-red-500";
              else if (hasHigh) hoverColor = "hover:border-orange-400";
              else if (hasLow) hoverColor = "hover:border-yellow-400";

              return (
                <div
                  key={i}
                  className={`relative p-3 rounded-2xl cursor-pointer text-center border border-white/10 transition-all hover:bg-white/10 hover:border-2 ${hoverColor}`}
                >
                  <div onClick={() => setSelectedIndex(i)}>
                    {f.file_name}
                  </div>

                  {/* ❌ REMOVE BUTTON */}
                  <button
                    onClick={() => removeResult(i)}
                    className="absolute top-1 right-2 text-xs opacity-0 hover:opacity-100 group-hover:opacity-100"
                  >
                    ❌
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Toggle */}
      <button
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className="absolute top-4 left-4 z-50 bg-black/60 px-2 py-1 rounded"
      >
        {sidebarOpen ? "←" : "→"}
      </button>

      {/* Main */}
      <div className="flex-1 p-6 overflow-y-auto">

        <h1 className="text-3xl font-bold text-center mb-6 font-mono">
          Log Security Dashboard
        </h1>

        {/* Upload */}
        <div
          onClick={() => inputRef.current.click()}
          onDrop={(e) => {
            e.preventDefault();
            setFiles([...files, ...Array.from(e.dataTransfer.files)]);
          }}
          onDragOver={(e) => e.preventDefault()}
          className="border-2 border-dashed border-white/30 p-8 py-15 rounded-xl text-center cursor-pointer bg-white/5 hover:bg-white/10 mb-4 font-mono"
        >
          Drag & Drop files or Click Here
          <input
            ref={inputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) =>
              setFiles([...files, ...Array.from(e.target.files)])
            }
          />
        </div>

        {/* Preview with REMOVE */}
        {files.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-4 justify-center">
            {files.map((f, i) => (
              <div key={i} className="relative bg-white/10 px-3 py-1 rounded-full">
                {f.name}

                <button
                  onClick={() => removeFile(i)}
                  className="ml-2 text-xs"
                >
                  ❌
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Analyze */}
        <div className="flex justify-center">
          <button
            onClick={handleUpload}
            className="bg-white hover:font-bold text-black hover:bg-amber-100 px-6 py-2 rounded-lg font-mono"
          >
            Analyze Files
          </button>
        </div>

        {/* Results */}
        {selected && (
          <div className="mt-6 space-y-6">

            <div className="bg-white/10 p-4 rounded-xl">
              <h2 className="text-xl font-bold">{selected.file_name}</h2>
              <p>{selected.summary}</p>
            </div>

            {/* Dropdown */}
            <details className="bg-white/10 p-4 rounded-xl">
              <summary className="cursor-pointer font-bold">
                View All Breaches ({selected.findings.length})
              </summary>

              <div className="mt-3 space-y-2">
                {selected.findings.map((f, i) => (
                  <div
                    key={i}
                    className={`px-3 py-1 rounded text-sm
                    ${
                      f.risk === "critical"
                        ? "bg-red-500/20 text-red-300"
                        : f.risk === "high"
                        ? "bg-orange-400/20 text-orange-300"
                        : "bg-yellow-300/20 text-yellow-200"
                    }`}
                  >
                    {f.line} → {f.value} ({f.risk})
                  </div>
                ))}
              </div>
            </details>

            {/* INSIGHTS */}
            <div className="bg-white/10 p-4 rounded-xl">
              <h3 className="font-bold">Insights</h3>
              {selected.insights.basic.map((i, idx) => (
                <p key={idx}>• {i}</p>
              ))}
            </div>

            {/* AI INSIGHTS */}
            {selected.insights.ai.length > 0 && (
              <div className="bg-white/10 p-4 rounded-xl border border-white/20">
                <h3 className="font-bold">AI Insights</h3>
                {selected.insights.ai.map((i, idx) => (
                  <p key={idx}>{i}</p>
                ))}
              </div>
            )}

            {/* NAVIGATION */}
            {selected.findings.length > 1 && (
              <div className="flex gap-4 justify-center">
                <button onClick={prevFinding} className="bg-white/10 px-4 py-2 rounded hover:bg-white/20">
                  ⬆ Prev
                </button>
                <button onClick={nextFinding} className="bg-white/10 px-4 py-2 rounded hover:bg-white/20">
                  ⬇ Next
                </button>
              </div>
            )}

            {/* Logs */}
            <div className="bg-black/70 max-h-[500px] overflow-y-auto rounded-xl border border-white/10 font-mono text-sm">
              {renderLines(selected.text, selected.findings)}
            </div>

          </div>
        )}
      </div>
    </div>
  );
}