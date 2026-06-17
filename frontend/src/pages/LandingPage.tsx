import { CursorGlow } from '../components/landing/CursorGlow'
import { Navbar } from '../components/landing/Navbar'
import { Hero } from '../components/landing/Hero'
import { Stats } from '../components/landing/Stats'
import { Features } from '../components/landing/Features'
import { HowItWorks } from '../components/landing/HowItWorks'
import { DashboardSection } from '../components/landing/DashboardSection'
import { TechStack } from '../components/landing/TechStack'
import { UseCases } from '../components/landing/UseCases'
import { CTA } from '../components/landing/CTA'
import { Footer } from '../components/landing/Footer'

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#09090B] text-white overflow-x-hidden">
      <CursorGlow />
      <Navbar />
      <Hero />
      <Stats />
      <Features />
      <HowItWorks />
      <DashboardSection />
      <TechStack />
      <UseCases />
      <CTA />
      <Footer />
    </div>
  )
}
