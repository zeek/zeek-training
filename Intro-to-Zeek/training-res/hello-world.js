zeek.on("zeek_init", () => {
    console.log("Hello, World!");
});

zeek.on("zeek_done", () => {
    console.log("Goodbye, World!");
});
