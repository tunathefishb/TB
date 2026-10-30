/* External ES6+ module loaded via <script src="widget.js"> */
function PrimeSieveLab(limit) {
    this.limit = limit || 200;
    this.primes = [];
}

PrimeSieveLab.prototype.compute = function () {
    const n = this.limit;
    const composite = [];
    for (let i = 0; i <= n; i++) composite.push(false);
    for (let p = 2; p * p <= n; p++) {
        if (!composite[p]) {
            for (let m = p * p; m <= n; m += p) composite[m] = true;
        }
    }
    const out = [];
    for (let i = 2; i <= n; i++) {
        if (!composite[i]) out.push(i);
    }
    this.primes = out;
    return out;
};

PrimeSieveLab.prototype.summary = function () {
    const count = this.primes.length;
    const sum = this.primes.reduce((acc, x) => acc + x, 0);
    const tail = this.primes.slice(-5).join(', ');
    return `${count} primes <= ${this.limit} | Sum: ${sum} | Largest 5: [${tail}]`;
};

window.TBExternalWidgetLoaded = true;
