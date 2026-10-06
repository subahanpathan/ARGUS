import { Card, CardContent } from '@/components/ui/card';
import { AlertCircle, LayoutDashboard } from 'lucide-react';
import { Link } from 'wouter';

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4">
      <Card className="w-full max-w-md border-border/40 bg-card/90 shadow-2xl backdrop-blur-md">
        <CardContent className="pt-6">
          <div className="flex mb-4 gap-3 items-center">
            <AlertCircle className="h-8 w-8 text-destructive shrink-0" />
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground">
                404 Page Not Found
              </h1>
              <p className="text-xs text-muted-foreground mt-0.5">
                The requested endpoint or view does not exist in the routing table.
              </p>
            </div>
          </div>

          <div className="mt-6 flex justify-end">
            <Link
              href="/dashboard"
              className="btn btn-primary inline-flex items-center gap-2 text-xs font-semibold px-4 py-2 rounded-md"
            >
              <LayoutDashboard size={14} />
              Return to Dashboard
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
