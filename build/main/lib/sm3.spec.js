"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ava_1 = __importDefault(require("ava"));
const sm3_1 = require("./sm3");
(0, ava_1.default)('abc', (t) => {
    const sm3 = new sm3_1.SM3();
    sm3.update('abc');
    const r = sm3.final('hex');
    t.is(r, '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');
});
(0, ava_1.default)('abcd', (t) => {
    const sm3 = new sm3_1.SM3();
    sm3.update('abcd'.repeat(16));
    const r = sm3.final('hex');
    t.is(r, 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732');
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic20zLnNwZWMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbGliL3NtMy5zcGVjLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsOENBQXVCO0FBRXZCLCtCQUE0QjtBQUU1QixJQUFBLGFBQUksRUFBQyxLQUFLLEVBQUUsQ0FBQyxDQUFDLEVBQUUsRUFBRTtJQUNoQixNQUFNLEdBQUcsR0FBRyxJQUFJLFNBQUcsRUFBRSxDQUFDO0lBQ3RCLEdBQUcsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDbEIsTUFBTSxDQUFDLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUMzQixDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsRUFBRSxrRUFBa0UsQ0FBQyxDQUFDO0FBQzlFLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBQSxhQUFJLEVBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQyxFQUFFLEVBQUU7SUFDakIsTUFBTSxHQUFHLEdBQUcsSUFBSSxTQUFHLEVBQUUsQ0FBQztJQUN0QixHQUFHLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQztJQUM5QixNQUFNLENBQUMsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQzNCLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxFQUFFLGtFQUFrRSxDQUFDLENBQUM7QUFDOUUsQ0FBQyxDQUFDLENBQUMifQ==